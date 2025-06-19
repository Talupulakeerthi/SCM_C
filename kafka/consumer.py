# kafka/consumer.py
from kafka import KafkaConsumer
from pymongo import MongoClient
import json
import os
from dotenv import load_dotenv # Import load_dotenv

# Load environment variables from the kafka/.env file
# Ensure the path is correct relative to where you run this script
load_dotenv(dotenv_path='./kafka/.env')

# --- Kafka Consumer Settings from .env ---
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "sensor_data")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "scmexpert_group")
KAFKA_AUTO_OFFSET_RESET = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")

# --- MongoDB Settings from .env ---
MONGODB_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "scmexpert")
MONGO_COLLECTION_NAME = os.getenv("MONGO_COLLECTION_NAME", "device_data")

# Basic validation for essential environment variables
if not KAFKA_BOOTSTRAP_SERVERS:
    raise ValueError("KAFKA_BOOTSTRAP_SERVERS not found in kafka/.env")
if not KAFKA_TOPIC:
    raise ValueError("KAFKA_TOPIC not found in kafka/.env")
if not MONGODB_URI:
    raise ValueError("MONGO_URI not found in kafka/.env")

# Initialize Kafka Consumer
try:
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(','), # Pass servers as a list
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset=KAFKA_AUTO_OFFSET_RESET,
        enable_auto_commit=True, # Auto commit offsets
        value_deserializer=lambda m: json.loads(m.decode('utf-8'))
    )
    print(f"Kafka consumer initialized for topic '{KAFKA_TOPIC}' with group_id '{KAFKA_GROUP_ID}'.")
except Exception as e:
    print(f"Failed to initialize Kafka consumer: {e}")
    exit(1)

# Initialize MongoDB Connection
try:
    client = MongoClient(MONGODB_URI)
    db = client[MONGO_DB_NAME]
    collection = db[MONGO_COLLECTION_NAME]
    print(f"MongoDB connection established to database '{MONGO_DB_NAME}', collection '{MONGO_COLLECTION_NAME}'.")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    exit(1)

print("Kafka consumer started. Waiting for messages...")

# Consume messages and insert into MongoDB
for message in consumer:
    data = message.value
    print(f"Received message: {data}")
    try:
        # Insert the received data into the MongoDB collection
        # MongoDB will automatically add an _id if not present
        collection.insert_one(data)
        print(f"Inserted into MongoDB: {data}")
    except Exception as e:
        print(f"Error inserting data into MongoDB: {e}. Data: {data}")
