import json
import time
from kafka import KafkaProducer
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path="./kafka_app/.env")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
TOPIC_USER = os.getenv("KAFKA_TOPIC_USER_ACTIVITIES", "user_activities")
TOPIC_SHIPMENT = os.getenv("KAFKA_TOPIC_SHIPMENT_STATUS", "shipment_status")
TOPIC_EVENT = os.getenv("KAFKA_TOPIC_EVENT_LOGS", "event_logs")

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

def log_user_activity(user_email, action, ip):
    data = {
        "user": user_email,
        "action": action,
        "ip": ip,
        "timestamp": int(time.time() * 1000)
    }
    producer.send(TOPIC_USER, data)
    producer.flush()

def log_shipment_status(shipment_id, status, updated_by):
    data = {
        "shipment_id": shipment_id,
        "status": status,
        "updated_by": updated_by,
        "timestamp": int(time.time() * 1000)
    }
    producer.send(TOPIC_SHIPMENT, data)
    producer.flush()

def log_event(event_type, message):
    data = {
        "event_type": event_type,
        "message": message,
        "timestamp": int(time.time() * 1000)
    }
    producer.send(TOPIC_EVENT, data)
    producer.flush()
