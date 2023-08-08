# Authstar

ASGI Middleware that can be configured with various authenticator functions
that are used to authenticate clients from the ASGI Scope. The authenticated
client information (`client_id`, `scopes`, etc.) is added to the ASGI Scope
and can be retrieved later in the request lifecycle in order to secure
routes, require additional authentication and/or make other decisions during
the request lifecycle.

In addition to the middleware, **Authstar** provides an extension that can be
used with **FastAPI** in order to reduce the boilerplate when securing routes
and providing an OAuth2 Token endpoint.

## Middleware

The middleware should be one of the first to run. If the application is using
some type of session middleware, the **AuthstarMiddleware** should be
configured to run just after the session middleware.

Example configuring the middleware for **FastAPI**:

```python
import fastapi
from authstar import AuthstarMiddleware, Client, HeaderAuth, Scope

app = fastapi.FastAPI()


async def on_auth_bearer(token: str) -> Client | None:
    ...


async def on_auth_basic(username: str, password: str) -> Client | None:
    ...


async def on_auth_api_key(token: str) -> Client | None:
    ...


async def on_auth_scope_session(scope: Scope) -> Client | None:
    ...


app.add_middleware(
    AuthstarMiddleware,
    on_auth_bearer=on_auth_bearer,
    on_auth_basic=on_auth_basic,
    on_auth_header=HeaderAuth.x_api_key(on_auth_api_key),
    on_auth_scope=on_auth_scope_session,
)
```

The `scope_key` parameter defines the dict key in the ASGI Scope where the
client information will be stored. The default is `authstar.client`. For
example, using `scope_key="users"` would match what the **Starlette**
Authentication Middleware uses and allow for using `request.user` if using
that framework or a framework built on **Starlette**.

The `AuthstarClient` model can be subclassed to allow for additional
attributes or methods to be added. If subclassing is not desired, any object
that implements the `authstar.Client` protocol can be used.

## FastAPI Extension

The `authstar.fastapi` module provides functionality that helps to reduce
boilerplate when securing routes.

The `authstar.fastapi.RouteSecurity` class can be configured to use the
same `scope_key` that the middleware uses in order to retrieve the stored
client information. The class provides several methods that can be used to
secure routes.

### Route Authorization

Once an instance is configured with the `scope_key`, the methods can be used
as dependencies in order to secure routes.

Here are some examples. Note that the dependencies can be added to a route,
router and/or the application:

```python
from typing import Annotated, Any

import authstar.fastapi
from authstar import Client
from fastapi import APIRouter, Security

route_security = authstar.fastapi.RouteSecurity()

insecure_router = APIRouter()
router = APIRouter(dependencies=[Security(route_security.authenticated)])


@insecure_router.get("/")
async def homepage():
    ...


@insecure_router.get("/healthcheck", dependencies=[Security(route_security.internal)])
async def healthcheck() -> dict[str, str]:
    """Returns HTTP 403 unless client is making request from an internal network.

    This example shows how to secure a route that should be accessible by
    unauthenticated clients where security is associated with some other
    request attribute (client ip in this case).
    """
    return {"status": "ok"}


@insecure_router.get("/foo", dependencies=[Security(route_security.authenticated)])
async def foo() -> dict[str, str]:
    """Returns HTTP 403 unless client is authenticated.

    This example shows how to secure the route if the security is not applied
    at the router level, and if the client information is not required. If
    the client information is required, then see the example below that uses
    the Annotated parameter.
    """
    return {"status": "bar"}


@router.get("/me")
async def me(
    auth_client: Annotated[Client, Security(route_security.authenticated)]
) -> dict[str, Any]:
    """Returns HTTP 403 unless client is unauthenticated.

    Also provides the client info as a parameter. The `router` is already
    secured and requires an authenticated client. This example shows that
    the client information can be retrieved as a parameter. Even if this
    route used the `insecure_router`, it would still be secured because
    of the Annotated parameter.
    """
    return auth_client.model_dump()


@router.get("/me2")
async def me2(
    auth_client: Annotated[Client, Security(route_security.scopes, scopes=["api-user"])]
) -> dict[str, Any]:
    """Returns HTTP 403 unless client is unauthenticated and has the given scope(s).

    Similar to the `authenticated` method, but also checks that the client has at
    least one of the specified scope values.
    """
    return auth_client.model_dump()
```

### OAuth2 Token Endpoint

The `RouteSecurity` class provides a convenience method that handles the
boilerplate required to serve an OAuth2 Token Endpoint. It supports the
`client_credentials` grant type and can handle client auth using either HTTP
Basic auth (handled by the **AuthstarMiddleware**) or by using the `client_id`
and `client_secret` form fields (requires an authenticator function).

If an `on_auth_basic` authenticator function is not provided, only HTTP Basic
Auth will be supported by the endpoint.

```python
from authstar import Client
from authstar.fastapi import OAuth2TokenRequest, OAuth2TokenResponse, RouteSecurity
from fastapi import APIRouter

router = APIRouter()
route_security = RouteSecurity()

async def oauth2_token_builder(
    oauth_req: OAuth2TokenRequest, client: Client
) -> OAuth2TokenResponse:
   # build a JWT and use it to return the response
   pass

async def verify_auth_basic(username: str, password: str) -> Client | None:
    pass

router.post("/oauth2/token")(
    route_security.oauth2_token_endpoint(
        token_builder=oauth2_token_builder,
        on_auth_basic=verify_auth_basic,
    )
)
```

### OpenAPI Available Authorizations

The `RouteSecurity` class provides a set of methods that return dependencies
that can be used to control the list of available authorizations that will be
listed in the generated `openapi.json`.

- `openapi_api_key`
- `openapi_http_basic`
- `openapi_oauth2_client_credentials`

When used as dependencies on a route, router and/or application, they enable
clients to authorize using the given methods at the OpenAPI endpoint client.
They are strictly no-op markers and do not perform any actual
authentication/authorization.

For example, adding the dependencies to the `router` below will enable the
OpenAPI docs endpoint client to prompt for either an API Key or client
credentials (`client_id`/`client_secret`):

```python
from authstar.fastapi import RouteSecurity
from fastapi import APIRouter

route_security = RouteSecurity()

router = APIRouter(
    dependencies=[
        route_security.openapi_api_key(),
        route_security.openapi_oauth2_client_credentials(),
    ],
)
```
