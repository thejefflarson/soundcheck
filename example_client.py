
Example API usage for login endpoint

import requests
import json

BASE_URL = "http://localhost:5000"

Register a new user
register_response = requests.post(
    f"{BASE_URL}/auth/register",
    json={
        "username": "john_doe",
        "email": "john@example.com",
        "password": "securepassword123"
    }
)
print("Register:", register_response.json())

Login with credentials
login_response = requests.post(
    f"{BASE_URL}/auth/login",
    json={
        "username": "john_doe",
        "password": "securepassword123"
    }
)
login_data = login_response.json()
print("Login:", login_data)

Get access token
access_token = login_data.get("access_token")

Use token to access protected endpoint
profile_response = requests.get(
    f"{BASE_URL}/api/me",
    headers={"Authorization": f"Bearer {access_token}"}
)
print("Profile:", profile_response.json())

Try with wrong password (should fail)
failed_login = requests.post(
    f"{BASE_URL}/auth/login",
    json={
        "username": "john_doe",
        "password": "wrongpassword"
    }
)
print("Failed Login:", failed_login.json())
