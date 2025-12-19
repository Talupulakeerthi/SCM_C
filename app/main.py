from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.openapi.utils import get_openapi
import os

# -------------------------------------------------
# App init FIRST
# -------------------------------------------------
app = FastAPI(title="SCMLite")

# -------------------------------------------------
# Config
# -------------------------------------------------
from .config import STATIC_DIR, TEMPLATES_DIR, logger

# -------------------------------------------------
# Static + Templates
# -------------------------------------------------
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.state.templates = templates   # ✅ REQUIRED

# -------------------------------------------------
# Session middleware
# -------------------------------------------------
from app.config import SESSION_SECRET_KEY

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY
)

# -------------------------------------------------
# Database
# -------------------------------------------------
from .database import users_collection, logins_collection

# -------------------------------------------------
# Security
# -------------------------------------------------
from .security import create_session_record, create_access_token

# -------------------------------------------------
# MFA (NOW SAFE TO INIT)
# -------------------------------------------------
from .mfa.mfa_router import router as mfa_router, init as mfa_init

mfa_init(
    templates,
    users_collection,
    logins_collection,
    create_session_record_func=create_session_record,
    create_access_token_func=create_access_token
)

app.include_router(mfa_router)

# -------------------------------------------------
# Routers
# -------------------------------------------------
from .routes import (
    auth_routes,
    dashboard_routes,
    user_routes,
    shipment_routes,
    device_data_routes,
)

app.include_router(auth_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(user_routes.router)
app.include_router(shipment_routes.router)
app.include_router(device_data_routes.router)

# -------------------------------------------------
# Root
# -------------------------------------------------
@app.get("/")
def root():
    return RedirectResponse(url="/login")

# -------------------------------------------------
# Exception handler
# -------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if request.headers.get("accept", "").startswith("text/html"):
        request.session["flash"] = exc.detail
        return RedirectResponse(url="/login")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# -------------------------------------------------
# OpenAPI (JWT lock icon)
# -------------------------------------------------
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="SCMLite API",
        version="1.0.0",
        routes=app.routes
    )

    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    unsecured = [
        "/",
        "/login",
        "/signup",
        "/logout",
        "/mfa/setup",
        "/mfa/relogin",
        "/mfa/verify",
    ]

    for path, methods in openapi_schema.get("paths", {}).items():
        for method in methods.values():
            if path not in unsecured:
                method["security"] = [{"BearerAuth": []}]
            else:
                method["security"] = []

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
