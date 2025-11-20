# test.py
"""
Test script for SCM_C project (FastAPI + MongoDB).
Includes tests for user signup/login, shipment creation, and basic API checks.
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000"

# -----------------------------
# User Tests
# -----------------------------
def test_signup():
    data = {
        "username": "testuser",
        "password": "Test@123",
        "email": "testuser@example.com"
    }
    try:
        resp = requests.post(f"{BASE_URL}/signup", json=data)
        print("Signup:", resp.status_code, resp.text)
    except Exception as e:
        print("Error in signup:", e)

def test_login():
    data = {
        "username": "testuser",
        "password": "Test@123"
    }
    try:
        resp = requests.post(f"{BASE_URL}/login", json=data)
        print("Login:", resp.status_code, resp.text)
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            return token
        return None
    except Exception as e:
        print("Error in login:", e)
        return None

# -----------------------------
# Shipment Tests
# -----------------------------
def test_create_shipment(token):
    headers = {"Authorization": f"Bearer {token}"}
    shipment_data = {
        "shipment_id": "TEST001",
        "sender": "Alice",
        "receiver": "Bob",
        "status": "Pending"
    }
    try:
        resp = requests.post(f"{BASE_URL}/shipments/create", json=shipment_data, headers=headers)
        print("Create shipment:", resp.status_code, resp.text)
    except Exception as e:
        print("Error in shipment creation:", e)

# -----------------------------
# Main execution
# -----------------------------
if __name__ == "__main__":
    print("Running SCM_C tests...")
    test_signup()
    token = test_login()
    if token:
        test_create_shipment(token)
