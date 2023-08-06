"""
Authstar Types
"""
import dataclasses
from collections.abc import Awaitable, Callable
from typing import Any, NamedTuple, Protocol, Self, TypeAlias

# ASGI Types used by the Middleware
Scope: TypeAlias = dict[str, Any]
Message: TypeAlias = dict[str, Any]
Receive: TypeAlias = Callable[[], Awaitable[Message]]
Send: TypeAlias = Callable[[Message], Awaitable[None]]
ASGIApp: TypeAlias = Callable[[Scope, Receive, Send], Awaitable[None]]


class Client(Protocol):
    """Defines the Client model that is stored in the Scope.

    Used to represent both authenticated and unauthenticated clients.
    """

    client_id: str
    scopes: list[str]
    is_authenticated: bool

    def model_dump(self) -> dict[str, Any]:
        """Returns a serialized version of this instance."""

    @classmethod
    def model_validate(cls, data: dict[str, Any]) -> Self:
        """Returns an instance of this type from a serialized version."""


@dataclasses.dataclass
class AuthstarClient(Client):
    """Default Client model implementation."""

    client_id: str
    scopes: list[str] = dataclasses.field(default_factory=list)
    is_authenticated: bool = False

    def __post_init__(self) -> None:
        self.is_authenticated = bool(self.client_id)

    def model_dump(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def model_validate(cls, model: dict[str, Any]) -> Self:
        return cls(**model)


@dataclasses.dataclass(frozen=True)
class UnauthenticatedAuthstarClient(Client):
    """Immutable Unauthenticated Client model.

    Model used when a client is not returned by any authenticators.
    """

    client_id: str = ""
    scopes: list[str] = dataclasses.field(default_factory=list)
    is_authenticated: bool = False

    def model_dump(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def model_validate(cls, data: dict[str, Any]) -> Self:
        if data.get("client_id"):
            raise ValueError("client_id", data["client_id"])
        if data.get("scopes"):
            raise ValueError("scopes", data["scopes"])
        if data.get("is_authenticated"):
            raise ValueError("is_authenticated", data["is_authenticated"])
        return cls()


# Singleton used to represent all unauthenticated clients
UNAUTHENTICATED_CLIENT = UnauthenticatedAuthstarClient()

# Async functions used to perform the various authentications
BasicAuthenticator: TypeAlias = Callable[[str, str], Awaitable[Client | None]]
TokenAuthenticator: TypeAlias = Callable[[str], Awaitable[Client | None]]
ScopeAuthenticator: TypeAlias = Callable[[Scope], Awaitable[Client | None]]


class HeaderAuth(NamedTuple):
    """Associates an authenticator with a particular header."""

    header_name: str
    authenticator: TokenAuthenticator

    @classmethod
    def x_api_key(cls, authenticator: TokenAuthenticator) -> Self:
        """Shortcut for creating an authenticator for the X-API-Key header."""
        return cls(header_name="x-api-key", authenticator=authenticator)


class AuthHeaderParseResult(NamedTuple):
    """The result of parsing the 'Authorization' header."""

    scheme: str
    token: str
