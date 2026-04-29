"""
Authstar ASGI Middleware for client authentication

Provides middleware that accepts various authenticator functions that are
used to identify clients making requests.
"""

from .middleware import AuthstarMiddleware, ContextMiddleware, LogMiddleware
from .types import (
    AuthstarClient,
    BasicAuthenticator,
    Client,
    HeaderAuth,
    Scope,
    ScopeAuthenticator,
    TokenAuthenticator,
)

__all__ = [
    "AuthstarClient",
    "AuthstarMiddleware",
    "BasicAuthenticator",
    "Client",
    "ContextMiddleware",
    "HeaderAuth",
    "LogMiddleware",
    "Scope",
    "ScopeAuthenticator",
    "TokenAuthenticator",
]
