# kafka_app/producer.py
from kafka import KafkaProducer
import json
import time
import random
import os
from dotenv import load_dotenv
from kafka.errors import NoBrokersAvailable
import time as _time

import socket

def detect_kafka_host():
    """
    Detect if running inside Docker or local machine.
    If Docker: hostname 'kafka' will resolve.
    If Local: fallback to localhost:9092.
    """
    try:
        socket.gethostbyname("kafka")   # will work only inside Docker network
        return "kafka:9092"
    except:
        return "localhost:9092"


# Load environment variables from the kafka/.env file
# Path is relative to project root where you usually run the script
load_dotenv(dotenv_path="./kafka_app/.env")

# --- Kafka Producer Settings from .env ---
KAFKA_BOOTSTRAP_SERVERS = detect_kafka_host()
print(f"[Kafka] Using bootstrap servers: {KAFKA_BOOTSTRAP_SERVERS}")

# Backward-compatible: old single topic name
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "sensor_data")

# New explicit topics
KAFKA_TOPIC_SENSOR = os.getenv("KAFKA_TOPIC_SENSOR", KAFKA_TOPIC)  # default to old name
KAFKA_TOPIC_SHIPMENT_STATUS = os.getenv("KAFKA_TOPIC_SHIPMENT_STATUS", "shipment_status")
KAFKA_TOPIC_USER_ACTIVITIES = os.getenv("KAFKA_TOPIC_USER_ACTIVITIES", "user_activities")
KAFKA_TOPIC_EVENT_LOGS = os.getenv("KAFKA_TOPIC_EVENT_LOGS", "event_logs")

PRODUCER_ACKS = os.getenv("PRODUCER_ACKS", "all")
PRODUCER_RETRIES = int(os.getenv("PRODUCER_RETRIES", "3"))

# --- Data Generation Settings from .env ---
DEVICE_ID_MIN = int(os.getenv("DEVICE_ID_MIN", "1000"))
DEVICE_ID_MAX = int(os.getenv("DEVICE_ID_MAX", "2000"))
BATTERY_LEVEL_MIN = float(os.getenv("BATTERY_LEVEL_MIN", "3.0"))
BATTERY_LEVEL_MAX = float(os.getenv("BATTERY_LEVEL_MAX", "5.0"))
TEMPERATURE_MIN = float(os.getenv("TEMPERATURE_MIN", "-10"))
TEMPERATURE_MAX = float(os.getenv("TEMPERATURE_MAX", "40"))

if not KAFKA_BOOTSTRAP_SERVERS:
    raise ValueError("KAFKA_BOOTSTRAP_SERVERS not found in kafka/.env")

# -----------------------------
# Producer singleton
# -----------------------------
_producer = None

class NoOpProducer:
    """Simple fallback producer that safely swallows sends when Kafka isn't available."""
    def send(self, *args, **kwargs):
        print("[Kafka][NoOpProducer] send() called - broker unavailable, message dropped.")
        class Fut:
            def get(self, timeout=None):
                return None
        return Fut()
    def flush(self):
        return None

def get_producer() -> KafkaProducer | NoOpProducer:
    """
    Lazily create and reuse a single KafkaProducer instance.
    Retries a few times if the broker isn't ready, then falls back to NoOpProducer.
    """
    global _producer
    if _producer is None:
        print(f"[Kafka] Connecting to: {KAFKA_BOOTSTRAP_SERVERS} ...")
        max_attempts = 5
        delay = 1  # seconds
        for attempt in range(1, max_attempts + 1):
            try:
                _producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
                    value_serializer=lambda x: json.dumps(x).encode("utf-8"),
                    acks=PRODUCER_ACKS,
                    retries=PRODUCER_RETRIES,
                )
                _producer.flush()
                print("[Kafka] Connected successfully.")
                break
            except NoBrokersAvailable as e:
                print(f"[Kafka] Broker not available (attempt {attempt}/{max_attempts}): {e}")
                if attempt == max_attempts:
                    print("[Kafka] Falling back to NoOpProducer — messages will be dropped until broker is reachable.")
                    _producer = NoOpProducer()
                else:
                    _time.sleep(delay)
                    delay = min(5, delay * 2)  # exponential-ish backoff
            except Exception as e:
                print(f"[Kafka] Unexpected error while connecting: {e}")
                _producer = NoOpProducer()
                break
    return _producer
# -----------------------------
# Sensor data (existing use-case)
# -----------------------------
def create_sensor_data():
    """
    Generates a dictionary of random sensor data based on configured ranges.
    Includes a timestamp for better data tracking and sorting in MongoDB.
    """
    return {
        "Device_ID": random.randint(DEVICE_ID_MIN, DEVICE_ID_MAX),
        "Battery_Level": round(random.uniform(BATTERY_LEVEL_MIN, BATTERY_LEVEL_MAX), 2),
        "First_Sensor_temperature": round(random.uniform(TEMPERATURE_MIN, TEMPERATURE_MAX), 1),
        "Route_From": "Chennai, India",
        "Route_To": "London, UK",
        "timestamp": int(time.time() * 1000),  # Unix timestamp in milliseconds
    }

def send_sensor_data():
    """Send one sensor_data message to its topic."""
    producer = get_producer()
    data = create_sensor_data()
    future = producer.send(KAFKA_TOPIC_SENSOR, value=data)
    record_metadata = future.get(timeout=10)
    print(
        f"[sensor_data] Sent: {data} "
        f"(topic={record_metadata.topic}, partition={record_metadata.partition}, offset={record_metadata.offset})"
    )
    producer.flush()

# -----------------------------
# NEW: Shipment status / user activities / event logs
# -----------------------------
def log_shipment_status(shipment_id: str, status: str, updated_by: str):
    """
    Log shipment status changes.
    Example: log_shipment_status("SHP123", "IN_TRANSIT", "admin@scm.com")
    """
    payload = {
        "shipment_id": shipment_id,
        "status": status,
        "updated_by": updated_by,
        "timestamp": int(time.time() * 1000),
    }
    producer = get_producer()
    producer.send(KAFKA_TOPIC_SHIPMENT_STATUS, value=payload)
    producer.flush()
    print(f"[shipment_status] Sent: {payload}")

def log_user_activity(user_email: str, action: str, ip_address: str = None):
    """
    Log high-level user actions.
    Example: log_user_activity("user@scm.com", "LOGIN_SUCCESS", "127.0.0.1")
    """
    payload = {
        "email": user_email,
        "action": action,
        "ip_address": ip_address,
        "timestamp": int(time.time() * 1000),
    }
    producer = get_producer()
    producer.send(KAFKA_TOPIC_USER_ACTIVITIES, value=payload)
    producer.flush()
    print(f"[user_activities] Sent: {payload}")


def log_event(event_name: str, metadata: dict | None = None):
    """
    General event logging.
    Example: log_event("ROLE_CHANGED", {"email": "x@y.com", "from": "user", "to": "admin"})
    """
    payload = {
        "event": event_name,
        "metadata": metadata or {},
        "timestamp": int(time.time() * 1000),
    }
    producer = get_producer()
    producer.send(KAFKA_TOPIC_EVENT_LOGS, value=payload)
    producer.flush()
    print(f"[event_logs] Sent: {payload}")

# -----------------------------
# CLI mode: keep your original loop
# -----------------------------
def main():
    """
    Main function: continuously sends sensor_data to Kafka.
    Other modules (FastAPI, scripts) can also import and call
    log_shipment_status / log_user_activity / log_event.
    """
    print(f"Starting to send sensor messages to topic: {KAFKA_TOPIC_SENSOR} ...")
    while True:
        try:
            send_sensor_data()
            time.sleep(5)  # Send a message every 5 seconds
        except Exception as e:
            print(f"Error sending message: {e}. Retrying in 1 second...")
            time.sleep(1)

if __name__ == "__main__":
    main()
