from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse
from typing import Optional
from datetime import datetime

from ..config import logger
from ..database import sensor_collection
from ..dependencies import get_current_user_from_token

router = APIRouter(tags=["Device Data"])


@router.get("/device-data", response_class=HTMLResponse)
async def device_data(
    request: Request,
    current_user: dict = Depends(get_current_user_from_token),
    device_id: Optional[str] = Query(default=None),
):
    logger.info(
        f"Device data accessed by {current_user.get('email')} "
        f"filter_device_id={device_id!r}"
    )

    match_condition = {}
    selected_device_id: Optional[int] = None

    if device_id:
        if device_id.isdigit():
            selected_device_id = int(device_id)
            match_condition["Device_ID"] = selected_device_id
        else:
            logger.warning(f"Invalid device_id value: {device_id!r}")

    pipeline = [
        {"$match": match_condition},
        {"$sort": {"timestamp": -1}},
        {
            "$group": {
                "_id": "$Device_ID",
                "latestRecord": {"$first": "$$ROOT"},
            }
        },
        {"$sort": {"latestRecord.timestamp": -1}},
        {"$limit": 10},
    ]

    results = list(sensor_collection.aggregate(pipeline))
    data = [r["latestRecord"] for r in results]

    # Post-process for UI display
    for item in data:
        item["_id"] = str(item.get("_id", ""))
        ts = item.get("timestamp")
        if ts:
            dt = datetime.fromtimestamp(ts / 1000)
            item["formatted_time"] = dt.strftime("%d %b %Y, %I:%M:%S %p")
        else:
            item["formatted_time"] = "N/A"

    device_ids = sorted(sensor_collection.distinct("Device_ID"))

    return request.app.state.templates.TemplateResponse(
        "device_data.html",
        {
            "request": request,
            "devices": data,
            "device_ids": device_ids,
            "selected_device_id": selected_device_id,
        },
    )
