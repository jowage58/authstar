import logging

import fastapi
import fastapi.exception_handlers
from starlette.middleware.sessions import SessionMiddleware

import authstar
import authstar.fastapi
from example import routes, security, settings

logger = logging.getLogger(__name__)

app = fastapi.FastAPI(
    debug=True,
    title="Authstar Test API",
    version=settings.api.version,
)

app.add_middleware(
    authstar.AuthstarMiddleware,
    on_auth_bearer=security.auth_bearer,
    on_auth_basic=security.auth_basic,
    on_auth_header=authstar.HeaderAuth.x_api_key(security.auth_api_key),
    on_auth_scope=security.auth_scope_session,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.api.secret_key,
    max_age=3600,
    same_site="strict",
    https_only=True,
)

app.include_router(routes.insecure_router)
app.include_router(
    routes.router,
    dependencies=[fastapi.Security(security.route_security.authenticated)],
)


@app.exception_handler(authstar.fastapi.UnauthorizedError)
async def on_unauthorized_error(
    request: fastapi.Request, exc: authstar.fastapi.UnauthorizedError
) -> fastapi.Response:
    logger.warning("on_unauthorized_error: %s - %r", request, exc)
    return await fastapi.exception_handlers.http_exception_handler(request, exc)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "example.app:app",
        log_level="info",
        reload=True,
    )


if __name__ == "__main__":
    run()
