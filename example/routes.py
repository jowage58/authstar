import logging
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Request,
    Response,
    Security,
)
from fastapi.responses import RedirectResponse

from .security import APIClient, oauth2_token_builder, route_security
from .security import auth_basic as auth_http_basic

logger = logging.getLogger(__name__)

router = APIRouter(
    dependencies=[
        route_security.openapi_http_basic(),
        route_security.openapi_oauth2_client_credentials(),
        route_security.openapi_api_key(),
    ],
)
insecure_router = APIRouter()

insecure_router.post(route_security.DEFAULT_OAUTH2_TOKEN_PATH)(
    route_security.oauth2_token_endpoint(
        token_builder=oauth2_token_builder,
        on_auth_basic=auth_http_basic,
    )
)


@insecure_router.get("/status")
async def api_status(
    client: Annotated[APIClient, Security(route_security.internal)]
) -> dict[str, Any]:
    return {
        "client": client,
    }


@router.get("/")
async def home_page() -> dict[str, str]:
    return {"page": "home"}


@insecure_router.get("/auth/login")
async def auth_basic(request: Request) -> Response:
    # pretend we got this in a form and validated the password
    username = "foo@bar.com"
    api_user = APIClient(
        client_id=username,
        scopes=["api:user", "api:dev"],
    )
    request.session["api_client"] = api_user.model_dump()
    return RedirectResponse(
        url=request.url_for("home_page"),
    )


@insecure_router.get("/auth/logout")
async def auth_logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse(
        url=request.url_for("home_page"),
    )


@router.get("/secret/scopes")
async def secret_route_scopes(
    api_client: Annotated[
        APIClient, Security(route_security.scopes, scopes=["api:dev2"])
    ]
) -> APIClient:
    return api_client


@router.get("/secret/authed")
async def secret_route_authenticated(
    api_client: Annotated[APIClient, Security(route_security.authenticated)]
) -> APIClient:
    return api_client
