# app/database.py
import pymongo  # Import the module first
from .config import MONGO_URI, DB_NAME, logger

# Use the full path to MongoClient to avoid namespace confusion
client = pymongo.MongoClient(MONGO_URI)
db = client[DB_NAME]

users_collection = db["user"]
logins_collection = db["logins"]
shipment_collection = db["shipments"]
sensor_collection = db["sensor_data_collection"]
sessions_collection = db["sessions"]
password_resets_collection = db["password_resets"]

def init_indexes():
    try:
        users_collection.create_index("email", unique=True)
        sessions_collection.create_index("session_id", unique=True)
        sessions_collection.create_index("expires_at", expireAfterSeconds=0)
    except Exception as e:
        logger.warning(f"Index creation warning: {e}")