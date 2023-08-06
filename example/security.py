import dataclasses
import logging
import time
import uuid
from typing import cast

import aiocache
import joserfc.jwt

from authstar import AuthstarClient, Client
from authstar import Scope as Scope  # noqa: PLC0414
from authstar.fastapi import OAuth2TokenRequest, OAuth2TokenResponse, RouteSecurity

from . import settings

logger = logging.getLogger(__name__)

route_security = RouteSecurity()

JWT_CLAIMS_ISSUER = "https://api.local"


@dataclasses.dataclass
class APIClient(AuthstarClient):
    email: str | None = None


async def oauth2_token_builder(
    oauth_req: OAuth2TokenRequest, client: Client
) -> OAuth2TokenResponse:
    now = int(time.time())
    client = cast(APIClient, client)
    payload = {
        "jti": uuid.uuid4().hex,
        "sub": client.client_id,
        "iss": JWT_CLAIMS_ISSUER,
        "iat": now,
        "exp": now + 3600,
        "scope": " ".join(client.scopes),
        "email": client.email,
    }
    token = joserfc.jwt.encode(
        header={"alg": "HS256"}, claims=payload, key=settings.api.secret_key
    )
    return OAuth2TokenResponse(
        access_token=token,
        scope=oauth_req.scope,
    )


async def auth_bearer(token: str) -> Client | None:
    logger.info("auth_bearer(%s)", token)
    jwt_token = joserfc.jwt.decode(
        value=token, key=settings.api.secret_key, algorithms=["HS256"]
    )
    joserfc.jwt.JWTClaimsRegistry(
        leeway=5.0,
        jti={"essential": True},
        sub={"essential": True},
        scope={"essential": True},
        email={"essential": True},
        iss={"essential": True, "value": JWT_CLAIMS_ISSUER},
    ).validate(jwt_token.claims)
    return APIClient(
        client_id=jwt_token.claims["sub"],
        scopes=jwt_token.claims["scope"].split(),
        email=jwt_token.claims["email"],
    )


@aiocache.cached(ttl=settings.api.auth_token_cache_ttl)  # type: ignore[misc]
async def auth_basic(username: str, password: str) -> Client | None:
    logger.info("auth_basic(%s, %s)", username, "*" * len(password))
    return APIClient(
        client_id="basic user", scopes=["api:user", "api:dev"], email="jdoe@foo.com"
    )


@aiocache.cached(ttl=settings.api.auth_token_cache_ttl)  # type: ignore[misc]
async def auth_api_key(token: str) -> Client | None:
    logger.info("auth_api_key(%s)", "*" * len(token))
    return APIClient(client_id="x-api-key user")


async def auth_scope_session(scope: Scope) -> Client | None:
    logger.info("auth_scope_session")
    if session_user := scope.get("session", {}).get("api_client"):
        return APIClient.model_validate(session_user)
    return None
