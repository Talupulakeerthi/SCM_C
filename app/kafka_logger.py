from kafka_app.producer import log_shipment_status, log_user_activity, log_event
from .config import logger

def safe_log_user_activity(email, action, ip=None):
    try:
        log_user_activity(email, action, ip)
    except Exception:
        logger.exception(f"Kafka error: user_activity {action}")

def safe_log_event(event_type, msg):
    try:
        log_event(event_type, msg)
    except Exception:
        logger.exception(f"Kafka error: event {event_type}")