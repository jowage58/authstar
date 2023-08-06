"""
Authstar ASGI Middleware
"""
import base64
import logging
from typing import ClassVar

from .types import (
    UNAUTHENTICATED_CLIENT,
    ASGIApp,
    AuthHeaderParseResult,
    BasicAuthenticator,
    Client,
    HeaderAuth,
    Receive,
    Scope,
    ScopeAuthenticator,
    Send,
    TokenAuthenticator,
)

logger = logging.getLogger(__name__)

HEADER_ENCODING = "iso-8859-1"


class AuthstarMiddleware:
    """
    Middleware that can be configured with various authenticator functions
    used to authenticate information from the ASGI Scope. The authenticated
    client info is then added to the ASGI Scope and can be retrieved later in
    the request lifecycle in order to secure routes, require additional
    authentication and/or make other decisions during the request lifecycle.

    Example of configuring the middleware using FastAPI:

    >>> from typing import Any

    >>> import authstar

    >>> async def on_auth_bearer(token: str) -> Client | None:
    >>>     ...

    >>> async def on_auth_basic(username: str, password: str) -> Client | None:
    >>>     ...

    >>> async def on_auth_api_key(token: str) -> Client | None:
    >>>     ...

    >>> async def on_auth_scope_session(scope: Scope) -> Client | None:
    >>>     ...

    >>> app: Any  # Starlette/FastAPI or other ASGI framework
    >>> app.add_middleware(
    >>>     authstar.AuthstarMiddleware,
    >>>     on_auth_bearer=on_auth_bearer,
    >>>     on_auth_basic=on_auth_basic,
    >>>     on_auth_header=authstar.HeaderAuth.x_api_key(on_auth_api_key),
    >>>     on_auth_scope=on_auth_scope_session,
    >>> )

    Only those authentication methods the application needs to support must be
    provided.
    """

    # This will be the key in the Scope where the Client instance is stored
    DEFAULT_SCOPE_KEY: ClassVar[str] = "authstar.client"

    def __init__(
        self,
        app: ASGIApp,
        *,
        scope_key: str = DEFAULT_SCOPE_KEY,
        on_auth_bearer: TokenAuthenticator | None = None,
        on_auth_basic: BasicAuthenticator | None = None,
        on_auth_header: HeaderAuth | None = None,
        on_auth_scope: ScopeAuthenticator | None = None,
    ) -> None:
        self.app = app
        self.scope_key = scope_key
        self.on_auth_bearer = on_auth_bearer
        self.on_auth_basic = on_auth_basic
        self.on_auth_header = on_auth_header
        self.on_auth_scope = on_auth_scope

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        try:
            auth_client = await self.auth_client_from(scope)
        except Exception:
            logger.exception(self)
            auth_client = None

        scope[self.scope_key] = (
            auth_client if auth_client is not None else UNAUTHENTICATED_CLIENT
        )

        await self.app(scope, receive, send)

    async def auth_client_from(self, scope: Scope) -> Client | None:
        if any((self.on_auth_bearer, self.on_auth_basic)) and (
            auth_parsed := parse_auth_header(scope)
        ):
            if self.on_auth_bearer is not None and auth_parsed.scheme == "bearer":
                return await self.on_auth_bearer(auth_parsed.token)
            if self.on_auth_basic is not None and auth_parsed.scheme == "basic":
                data = base64.b64decode(auth_parsed.token).decode(HEADER_ENCODING)
                basic_credentials = data.split(":")
                return await self.on_auth_basic(*basic_credentials)

        if self.on_auth_header is not None and (
            header_token := header_value_from(scope, self.on_auth_header.header_name)
        ):
            return await self.on_auth_header.authenticator(header_token)

        if self.on_auth_scope is not None:
            return await self.on_auth_scope(scope)

        return None

    def __repr__(self) -> str:
        auth_methods = []
        if self.on_auth_bearer is not None:
            auth_methods.append("bearer")
        if self.on_auth_basic is not None:
            auth_methods.append("basic")
        if self.on_auth_header is not None:
            auth_methods.append("header")
        if self.on_auth_scope is not None:
            auth_methods.append("scope")
        return (
            f"{self.__class__.__qualname__}(scope_key={self.scope_key!r}"
            f", methods={auth_methods!r})"
        )


def parse_auth_header(scope: Scope) -> AuthHeaderParseResult | None:
    """Returns a parsed 'Authorization', including the scheme and value."""
    auth_header = header_value_from(scope, b"authorization")
    return parse_auth_header_value(auth_header)


def parse_auth_header_value(header_value: str | None) -> AuthHeaderParseResult | None:
    """Returns the parsed result from the 'Authorization' header

    If the provided header value is None or if the format of the given value
    is not '<scheme> <value>', None will be returned. The 'scheme' will be
    lower-cased and any extra spaces between the 'scheme' and 'value' will be
    ignored.
    """
    if not header_value:
        return None
    scheme, sep, token = header_value.partition(" ")
    return AuthHeaderParseResult(scheme.lower(), token.lstrip()) if sep else None


def header_value_from(scope: Scope, header_name: bytes | str) -> str | None:
    """Returns the header value from the Scope, else None.

    If multiple values are set for the given header name, the first value
    will be returned.
    """
    name = header_name.lower()
    if isinstance(name, str):
        name = name.encode(HEADER_ENCODING)
    k: bytes
    v: bytes
    for k, v in scope["headers"]:
        if k.lower() == name:
            return v.decode(HEADER_ENCODING)
    return None
