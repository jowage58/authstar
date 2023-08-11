"""
Authstar FastAPI extension

Provides route security and an OAuth2 token endpoint.
"""
import collections.abc
import dataclasses
import ipaddress
import logging
import typing

import fastapi
import fastapi.openapi.models
import fastapi.responses
import fastapi.security

from .middleware import AuthstarMiddleware
from .types import BasicAuthenticator, Client

logger = logging.getLogger(__name__)


class UnauthorizedError(fastapi.HTTPException):
    """HTTP 401 Unauthorized Error."""

    def __init__(
        self,
        client: Client,
        detail: typing.Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=401, detail=detail, headers=headers)
        self.client = client


class ForbiddenError(fastapi.HTTPException):
    """HTTP 403 Forbidden Error."""

    def __init__(
        self,
        client: Client,
        detail: typing.Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=403, detail=detail, headers=headers)
        self.client = client


@dataclasses.dataclass
class OAuth2TokenRequest:
    """OAuth2 Token Request.

    Represents the form values that are sent via POST to an OAuth2 Token
    endpoint.
    """

    grant_type: str
    scope: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


@dataclasses.dataclass
class OAuth2TokenResponse:
    """OAuth2 Token Response.

    Represents the values returned in JSON format from an OAuth2 Token
    endpoint.
    """

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: str | None = None
    scope: str | None = None


# Async function that can create an OAuth2 token response
OAuth2TokenResponseBuilder: typing.TypeAlias = collections.abc.Callable[
    [OAuth2TokenRequest, Client], collections.abc.Awaitable[OAuth2TokenResponse]
]


class HTTPBasic(fastapi.security.HTTPBasic):
    """OpenAPI Model for HTTP Basic Authentication.

    Actual authentication is handled by the middleware. This is a marker used
    by the OpenAPI docs to prompt for HTTP Basic authentication.
    """

    async def __call__(  # type: ignore[override]
        self, request: fastapi.Request  # noqa: ARG002
    ) -> fastapi.security.HTTPBasicCredentials | None:
        return None


class APIKeyHeader(fastapi.security.APIKeyHeader):
    """OpenAPI Model for API Key Authentication.

    Actual authentication is handled by the middleware. This is a marker used
    by the OpenAPI docs to prompt for an API Key token value.
    """

    async def __call__(self, request: fastapi.Request) -> str | None:  # noqa: ARG002
        return None


class OAuth2ClientCredentials(fastapi.security.OAuth2):
    """OpenAPI Model for OAuth2 Client Credentials Authentication.

    Actual authentication is handled by the middleware. This is a marker used
    by the OpenAPI docs to prompt for Client Credentials authentication.
    """

    def __init__(
        self,
        *,
        token_url: str,
        scheme_name: str | None = None,
        scopes: dict[str, str] | None = None,
        description: str | None = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = fastapi.openapi.models.OAuthFlows(
            clientCredentials=fastapi.openapi.models.OAuthFlowClientCredentials(
                tokenUrl=token_url, scopes=scopes
            ),
        )
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: fastapi.Request) -> str | None:  # noqa: ARG002
        return None


class RouteSecurity:
    """Route Security using the AuthstarMiddleware.

    Provides various methods that can be used as dependencies on a route
    in order to perform authorization.

    The instance must be configured with the key to lookup in the ASGI Scope
    to find an instance of an 'authstar.Client'.
    """

    DEFAULT_OAUTH2_TOKEN_PATH = "/oauth2/token"  # noqa: S105

    def __init__(
        self,
        *,
        scope_key: str = AuthstarMiddleware.DEFAULT_SCOPE_KEY,
        is_admin_attribute: str | None = None,
    ) -> None:
        """The 'scope_key' should match the one used to configure the
        AuthstarMiddleware. The key is used to retrieve the client information
        from the Scope.

        If `is_admin_attribute` is defined and that attribute returns a True
        value then scope checks will be bypassed.
        """
        self.scope_key = scope_key
        self.is_admin_attribute = is_admin_attribute

    def client(self, request: fastapi.Request) -> Client:
        """Returns the client from the given Request."""
        return typing.cast(Client, request.scope[self.scope_key])

    def internal(self, request: fastapi.Request) -> Client:
        """Returns the client if the request was made from an internal network.

        This method is designed to be used as a route dependency for any route that
        should only allow clients that are coming from internal networks.

        If the client is not making the request from an internal network, an HTTP
        403 status will be returned.

        For example, if the application provides a healthcheck endpoint that only a
        fronting load balancer/proxy should access and that access is made via an
        internal network, the route can be configured as the following example:

        >>> from authstar.fastapi import RouteSecurity
        >>> from fastapi import APIRouter, Security

        >>> router = APIRouter()
        >>> route_security = RouteSecurity()

        >>> @router.get(
        >>>     "/healthcheck",
        >>>     dependencies=[Security(route_security.internal)],
        >>> )
        >>> async def healthcheck() -> dict[str, str]:
        >>>    return {"status": "ok"}
        """
        auth_client = self.client(request)
        if (client := request.client) and ipaddress.ip_address(client.host).is_private:
            return auth_client
        raise ForbiddenError(client=auth_client)

    def authenticated(self, request: fastapi.Request) -> Client:
        """Returns the client if the request came from an authenticated client.

        This method is designed to be used as a route dependency for any route that
        should only allow clients that are unathenticated.

        If the client is not making the request is not authenticated, an HTTP
        401 Unauthorized will be returned.

        For example, a route can be configured as the following example:

        >>> from typing import Annotated, Any

        >>> from authstar import Client
        >>> from authstar.fastapi import RouteSecurity
        >>> from fastapi import APIRouter, Security

        >>> router = APIRouter()
        >>> route_security = RouteSecurity()

        >>> @router.get("/foo", dependencies=[Security(route_security.authenticated)])
        >>> async def foo() -> dict[str, str]:
        >>>    return {"status": "bar"}

        To secure the endpoint and also get access to the client information:

        >>> @router.get("/me")
        >>> async def me(
        >>>     client: Annotated[
        >>>         Client, Security(route_security.authenticated)]
        >>> ) -> dict[str, Any]:
        >>>    return auth_client.model_dump()
        """
        auth_client = self.client(request)
        if auth_client.is_authenticated:
            return auth_client
        raise UnauthorizedError(client=auth_client)

    def scopes(
        self, request: fastapi.Request, scopes: fastapi.security.SecurityScopes
    ) -> Client:
        """Returns a client if it has at least one of the specified scopes.

        This method is designed to be used as a route dependency for any route
        that should only allow clients that have been granted the necessary
        scope(s).

        If an unauthenticated client is making the request an HTTP 401
        Unauthorized will be returned. If the client is authenticated but
        does not possess any of the required scopes, an HTTP 403 status will
        be returned.

        For example, a route can be configured as the following example:

        >>> from typing import Annotated, Any

        >>> from authstar import Client
        >>> from authstar.fastapi import RouteSecurity
        >>> from fastapi import APIRouter, Security

        >>> router = APIRouter()
        >>> route_security = RouteSecurity()

        >>> @router.get(
        >>>     "/foo",
        >>>     dependencies=[Security(route_security.scopes, scopes=["api-user"])]
        >>> )
        >>> async def foo() -> dict[str, str]:
        >>>    return {"status": "bar"}

        To secure the endpoint and also get access to the client information:

        >>> @router.get("/me")
        >>> async def me(
        >>>     client: Annotated[
        >>>         Client,
        >>>         Security(route_security.scopes, scopes=["api-user"])
        >>>     ]
        >>> ) -> dict[str, Any]:
        >>>    return client.model_dump()
        """
        auth_client = self.authenticated(request)
        if not scopes.scopes:
            return auth_client
        if self.is_admin_attribute is not None and getattr(
            auth_client, self.is_admin_attribute
        ):
            return auth_client
        if set(auth_client.scopes) & set(scopes.scopes):
            return auth_client
        raise ForbiddenError(client=auth_client)

    @staticmethod
    def openapi_api_key(
        *,
        name: str = "x-api-key",
        scheme_name: str | None = None,
        description: str | None = None,
    ) -> typing.Any:
        """OpenAPI API Key authorization.

        Marker used to add API Key to the list of available
        authorizations to the OpenAPI docs. This does not perform any
        authentication/authorization, it serves only as an indicator to the
        OpenAPI generator that this form of authentication is available.
        """
        return fastapi.Depends(
            APIKeyHeader(name=name, scheme_name=scheme_name, description=description)
        )

    @staticmethod
    def openapi_http_basic(
        *,
        scheme_name: str | None = None,
        realm: str | None = None,
        description: str | None = None,
    ) -> typing.Any:
        """OpenAPI HTTP Basic Authentication authorization.

        Marker used to add HTTP Basic Auth to the list of available
        authorizations to the OpenAPI docs. This does not perform any
        authentication/authorization, it serves only as an indicator to the
        OpenAPI generator that this form of authentication is available.
        """
        return fastapi.Depends(
            HTTPBasic(scheme_name=scheme_name, realm=realm, description=description)
        )

    @staticmethod
    def openapi_oauth2_client_credentials(
        *,
        token_url: str = DEFAULT_OAUTH2_TOKEN_PATH,
        scheme_name: str | None = None,
        scopes: dict[str, str] | None = None,
        description: str | None = None,
    ) -> typing.Any:
        """OpenAPI OAuth2 Client Credentials authorization.

        Marker used to add OAuth2 Client Credentials to the list of available
        authorizations to the OpenAPI docs. This does not perform any
        authentication/authorization, it serves only as an indicator to the
        OpenAPI generator that this form of authentication is available.
        """
        return fastapi.Depends(
            OAuth2ClientCredentials(
                token_url=token_url,
                scheme_name=scheme_name,
                scopes=scopes,
                description=description,
            )
        )

    def oauth2_token_endpoint(
        self,
        *,
        token_builder: OAuth2TokenResponseBuilder,
        on_auth_basic: BasicAuthenticator | None = None,
    ) -> collections.abc.Callable[
        ..., collections.abc.Awaitable[fastapi.responses.JSONResponse]
    ]:
        """Returns an OAuth2 Token Endpoint API route function.

        This is a convenience method that handles the boilerplate required to
        serve an OAuth2 Token Endpoint. It supports the 'client_credentials'
        grant type and can handle client auth using either HTTP Basic auth
        (handled by the AuthstarMiddleware) or by using the `client_id`/
        `client_secret` form fields.

        If an 'on_auth_basic' function is not provided or None, only
        HTTP Basic Auth will be supported.

        An example of configuring this route:

        >>> from authstar import Client
        >>> from authstar.fastapi import (
        >>>     OAuth2TokenRequest,
        >>>     OAuth2TokenResponse,
        >>>     RouteSecurity,
        >>> )
        >>> from fastapi import APIRouter

        >>> router = APIRouter()
        >>> route_security = RouteSecurity()

        >>> async def oauth2_token_builder(
        >>>    oauth_req: OAuth2TokenRequest, client: Client
        >>> ) -> OAuth2TokenResponse:
        >>>    # build a JWT and use it to return the response
        >>>    pass

        >>> async def verify_auth_basic(
        >>>     username: str, password: str
        >>> ) -> Client | None:
        >>>     pass

        >>> router.post("/oauth2/token")(
        >>>    route_security.oauth2_token_endpoint(
        >>>        token_builder=oauth2_token_builder,
        >>>        on_auth_basic=verify_auth_basic,
        >>>    )
        >>>  )
        """

        async def _oauth2_token_route(
            request: fastapi.Request,
            grant_type: typing.Annotated[str | None, fastapi.Form()] = None,
            scope: typing.Annotated[str | None, fastapi.Form()] = None,
            client_id: typing.Annotated[str | None, fastapi.Form()] = None,
            client_secret: typing.Annotated[str | None, fastapi.Form()] = None,
        ) -> fastapi.responses.JSONResponse:
            auth_client = self.client(request)
            if (
                not auth_client.is_authenticated
                and on_auth_basic is not None
                and client_id is not None
                and client_secret is not None
            ):
                try:
                    basic_auth_client = await on_auth_basic(client_id, client_secret)
                except Exception:
                    logger.exception("basic auth from client_id/client_secret failed")
                else:
                    if basic_auth_client:
                        auth_client = basic_auth_client

            if grant_type is None:
                error_msg = "invalid_request"
                error_descr = "Missing required 'grant_type' parameter"
                logger.warning("%s: %s - %s", auth_client, error_msg, error_descr)
                return fastapi.responses.JSONResponse(
                    content={
                        "error": error_msg,
                        "error_description": error_descr,
                    },
                    status_code=400,
                )

            if grant_type != "client_credentials":
                error_msg = "unsupported_grant_type"
                error_descr = (
                    f"The grant_type '{grant_type}' is not supported, "
                    "only 'client_credentials' is allowed."
                )
                logger.warning("%s: %s - %s", auth_client, error_msg, error_descr)
                return fastapi.responses.JSONResponse(
                    content={
                        "error": error_msg,
                        "error_description": error_descr,
                    },
                    status_code=400,
                )

            if not auth_client.is_authenticated:
                error_msg = "invalid_client"
                logger.warning("%s: %s", auth_client, error_msg)
                return fastapi.responses.JSONResponse(
                    content={"error": error_msg},
                    status_code=401,
                )

            if scope:
                requested_scopes = set(scope.split())
                client_scopes = set(auth_client.scopes)
                if missing_scopes := requested_scopes - client_scopes:
                    error_msg = "invalid_scope"
                    error_descr = (
                        "Client is not authorized for scopes: "
                        f"{', '.join(missing_scopes)}"
                    )
                    logger.warning("%s: %s - %s", auth_client, error_msg, error_descr)
                    return fastapi.responses.JSONResponse(
                        content={
                            "error": error_msg,
                            "error_description": error_descr,
                        },
                        status_code=400,
                    )

            oauth2_request = OAuth2TokenRequest(
                grant_type=grant_type,
                scope=scope,
                client_id=client_id,
                client_secret=client_secret,
            )
            token_response = await token_builder(oauth2_request, auth_client)
            payload = dataclasses.asdict(token_response)
            if payload["refresh_token"] is None:
                del payload["refresh_token"]
            if payload["scope"] is None:
                del payload["scope"]

            response = fastapi.responses.JSONResponse(content=payload)
            response.headers["cache-control"] = "no-store"
            return response

        return _oauth2_token_route
