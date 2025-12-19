from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from datetime import datetime

from ..config import logger
from ..database import users_collection, sessions_collection
from ..dependencies import get_current_admin_user
from ..email_utils import send_email

router = APIRouter(tags=["User Management"])


@router.get("/user_management", response_class=HTMLResponse)
def user_management(
    request: Request,
    current_user: dict = Depends(get_current_admin_user)
):
    logger.info(f"User management accessed by {current_user.get('email')}")
    users = list(
        users_collection.find({}, {"_id": 0, "name": 1, "email": 1, "role": 1})
    )
    return request.app.state.templates.TemplateResponse(
        "user_management.html",
        {
            "request": request,
            "users": users
        }
    )


@router.get("/active_sessions", response_class=HTMLResponse)
def get_active_sessions(
    request: Request,
    current_user: dict = Depends(get_current_admin_user)
):
    sessions = list(sessions_collection.find({}, {"_id": 0}))
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse(
        "active_sessions.html",
        {
            "request": request,
            "sessions": sessions,
            "flash": flash
        }
    )


@router.post("/revoke_session/{session_id}")
def revoke_session_admin(
    session_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin_user)
):
    result = sessions_collection.update_one(
        {"session_id": session_id},
        {"$set": {"revoked": True}}
    )
    request.session["flash"] = (
        "Session revoked successfully."
        if result.modified_count
        else "Session not found."
    )
    return RedirectResponse("/active_sessions", status_code=302)


@router.get("/edit-users/{email}", response_class=HTMLResponse)
async def get_edit_user(
    request: Request,
    email: str,
    current_user: dict = Depends(get_current_admin_user)
):
    user = users_collection.find_one({"email": email})
    if not user:
        request.session["flash"] = "User not found."
        return RedirectResponse(url="/user_management", status_code=302)

    return request.app.state.templates.TemplateResponse(
        "edit_user.html",
        {
            "request": request,
            "user": user,
            "flash": request.session.pop("flash", None)
        }
    )


@router.post("/update-user")
async def update_user(
    request: Request,
    old_email: str = Form(...),
    name: str = Form(...),
    new_email: str = Form(...),
    role: str = Form(...),
    current_user: dict = Depends(get_current_admin_user),
):
    old_user = users_collection.find_one({"email": old_email})
    if not old_user:
        request.session["flash"] = "User not found."
        return RedirectResponse("/user_management", status_code=302)

    users_collection.update_one(
        {"email": old_email},
        {"$set": {"name": name, "email": new_email, "role": role}}
    )

    subject = "Your SCMLite Account Was Updated"
    body = (
        f"Hello {name},\n\n"
        "Your account has been updated by an administrator.\n"
        f"Updated By: {current_user.get('email')}"
    )
    send_email(new_email, subject, body)

    request.session["flash"] = "User updated successfully."
    return RedirectResponse("/user_management", status_code=302)


@router.get("/assign-admin/{email}")
def assign_admin(
    email: str,
    request: Request,
    current_user: dict = Depends(get_current_admin_user)
):
    user = users_collection.find_one({"email": email})
    if user and user.get("role") != "admin":
        users_collection.update_one(
            {"email": email},
            {"$set": {"role": "admin"}}
        )
        send_email(
            email,
            "Role Updated to ADMIN",
            "Your role has been updated to ADMIN in SCMLite."
        )
        request.session["flash"] = f"{email} is now an admin."

    return RedirectResponse("/user_management", status_code=302)
