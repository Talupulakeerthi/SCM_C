# kafka/producer.py
from kafka import KafkaProducer
import json
import time
import random
import os
from dotenv import load_dotenv # Import load_dotenv

# Load environment variables from the kafka/.env file
# Ensure the path is correct relative to where you run this script
load_dotenv(dotenv_path='./kafka/.env')

# --- Kafka Producer Settings from .env ---
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "sensor_data")
PRODUCER_ACKS = os.getenv("PRODUCER_ACKS", "all")
PRODUCER_RETRIES = int(os.getenv("PRODUCER_RETRIES", "3"))
# PRODUCER_RETRY_BACKOFF_MS is not directly used in the current KafkaProducer constructor,
# but it's good to have in .env for future enhancements.

# --- Data Generation Settings from .env ---
DEVICE_ID_MIN = int(os.getenv("DEVICE_ID_MIN", "1000"))
DEVICE_ID_MAX = int(os.getenv("DEVICE_ID_MAX", "2000"))
BATTERY_LEVEL_MIN = float(os.getenv("BATTERY_LEVEL_MIN", "3.0"))
BATTERY_LEVEL_MAX = float(os.getenv("BATTERY_LEVEL_MAX", "5.0"))
TEMPERATURE_MIN = float(os.getenv("TEMPERATURE_MIN", "-10"))
TEMPERATURE_MAX = float(os.getenv("TEMPERATURE_MAX", "40"))

# Basic validation for essential environment variables
if not KAFKA_BOOTSTRAP_SERVERS:
    raise ValueError("KAFKA_BOOTSTRAP_SERVERS not found in kafka/.env")
if not KAFKA_TOPIC:
    raise ValueError("KAFKA_TOPIC not found in kafka/.env")

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
        "timestamp": int(time.time() * 1000) #  Unix timestamp in milliseconds
    }

def main():
    """
    Main function to initialize Kafka producer and send sensor data periodically.
    """
    print(f"Connecting to Kafka at: {KAFKA_BOOTSTRAP_SERVERS}...")
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(','), # Pass servers as a list
            value_serializer=lambda x: json.dumps(x).encode('utf-8'),
            acks=PRODUCER_ACKS,
            retries=PRODUCER_RETRIES
        )
        producer.flush() # Ensure connection is established
        print("Connected to Kafka successfully.")
    except Exception as e:
        print(f"Failed to connect to Kafka: {e}")
        # Exit if connection fails, as producer cannot function
        exit(1)

    print(f"Starting to send messages to topic: {KAFKA_TOPIC}...")
    while True:
        try:
            data = create_sensor_data()
            future = producer.send(KAFKA_TOPIC, value=data)
            record_metadata = future.get(timeout=10) # Block until a result is received or timeout
            print(f"Sent data: {data} to topic {record_metadata.topic}, partition {record_metadata.partition}, offset {record_metadata.offset}")
            producer.flush() # Ensure message is sent
            time.sleep(5)  # Send a message every 5 seconds
        except Exception as e:
            print(f"Error sending message: {e}. Retrying in 1 second...")
            time.sleep(1)

if __name__ == "__main__":
    main()
