# kafka/consumer.py
from kafka import KafkaConsumer
from pymongo import MongoClient
import json
import os
from dotenv import load_dotenv

# Load environment variables from kafka/.env
load_dotenv(dotenv_path='./kafka/.env')

# Kafka settings
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "scmexpert_group")
KAFKA_AUTO_OFFSET_RESET = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")

# Topics (from updated .env)
TOPIC_SENSOR = os.getenv("KAFKA_TOPIC_SENSOR", "sensor_data")
TOPIC_SHIPMENT = os.getenv("KAFKA_TOPIC_SHIPMENT_STATUS", "shipment_status")
TOPIC_ACTIVITY = os.getenv("KAFKA_TOPIC_USER_ACTIVITIES", "user_activities")
TOPIC_EVENT = os.getenv("KAFKA_TOPIC_EVENT_LOGS", "event_logs")

topics = [TOPIC_SENSOR, TOPIC_SHIPMENT, TOPIC_ACTIVITY, TOPIC_EVENT]

# MongoDB Settings
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "SCMLiteDB")

if not MONGO_URI:
    raise ValueError("MONGO_URI missing in .env")

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]

# Collections for each topic
collection_sensor = db.get_collection("sensor_data_collection")
collection_shipment = db.get_collection("shipment_status_logs")
collection_activity = db.get_collection("user_activity_logs")
collection_event = db.get_collection("event_logs")

print("[MongoDB] Connected successfully.")

# Initialize Kafka Consumer
consumer = KafkaConsumer(
    *topics,
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
    group_id=KAFKA_GROUP_ID,
    auto_offset_reset=KAFKA_AUTO_OFFSET_RESET,
    enable_auto_commit=True,
    value_deserializer=lambda x: json.loads(x.decode("utf-8")),
)

print("[Kafka] Subscribed to topics:", topics)
print("[Consumer] Waiting for messages...\n")

# Route messages to appropriate MongoDB collections
for msg in consumer:
    topic = msg.topic
    data = msg.value

    print(f"\n🔔 Received from {topic}")
    print(f"Data: {data}")

    try:
        if topic == TOPIC_SENSOR:
            collection_sensor.insert_one(data)
            print("[MongoDB] Inserted into sensor_data_collection")

        elif topic == TOPIC_SHIPMENT:
            collection_shipment.insert_one(data)
            print("[MongoDB] Inserted into shipment_status_logs")

        elif topic == TOPIC_ACTIVITY:
            collection_activity.insert_one(data)
            print("[MongoDB] Inserted into user_activity_logs")

        elif topic == TOPIC_EVENT:
            collection_event.insert_one(data)
            print("[MongoDB] Inserted into event_logs")

        else:
            print("[WARN] Unknown topic, not inserted.")

    except Exception as e:
        print(f"[ERROR] Failed to insert into MongoDB: {e}")
