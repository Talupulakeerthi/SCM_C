from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from datetime import datetime

from ..dependencies import get_current_admin_user, get_current_user_from_token
from ..database import shipment_collection
from ..config import logger

router = APIRouter()

@router.get("/edit-shipment", response_class=HTMLResponse)
def get_edit_shipment(
    request: Request,
    current_user: dict = Depends(get_current_admin_user),
):
    logger.info(f"Edit shipment accessed by {current_user.get('email')}")
    flash = request.session.pop("flash", None)

    shipments = list(shipment_collection.find({}, {"_id": 0}))

    return request.app.state.templates.TemplateResponse(
        "edit_shipment.html",
        {
            "request": request,
            "shipments": shipments,
            "flash": flash,
        },
    )
