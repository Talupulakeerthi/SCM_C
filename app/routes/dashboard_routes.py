from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse

from ..dependencies import (
    get_current_user_from_token,
    get_current_admin_user,
)
from ..config import logger

router = APIRouter()

# =========================================================
# USER DASHBOARD
# =========================================================

@router.get("/dashboard", response_class=HTMLResponse)
def user_dashboard(
    request: Request,
    current_user: dict = Depends(get_current_user_from_token),
):
    """
    Normal user dashboard.
    Accessed AFTER MFA success.
    """
    logger.info(f"User dashboard accessed by {current_user.get('email')}")

    return request.app.state.templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "name": current_user.get("name"),
            "role": current_user.get("role"),
        },
    )


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@router.get("/admin-dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    current_user: dict = Depends(get_current_admin_user),
):
    """
    Admin dashboard.
    Admins DO NOT use MFA.
    """
    logger.info(f"Admin dashboard accessed by {current_user.get('email')}")

    return request.app.state.templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "name": current_user.get("name"),
            "role": current_user.get("role"),
        },
    )
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    current_user: dict = Depends(get_current_user_from_token),
):
    logger.info(f"Dashboard accessed by {current_user['email']}")
    return request.app.state.templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "name": current_user.get("name"),
            "role": current_user.get("role"),
        },
    )