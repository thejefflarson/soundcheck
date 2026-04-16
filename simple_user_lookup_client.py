import requests
import json

BASE_URL = 'http://localhost:5000'


def seed_database():
    """Add sample users to the database."""
    response = requests.post(f'{BASE_URL}/api/users/seed')
    print("Seeding database:")
    print(json.dumps(response.json(), indent=2))
    print()


def list_all_users():
    """List all users in the database."""
    response = requests.get(f'{BASE_URL}/api/users')
    print("All users:")
    print(json.dumps(response.json(), indent=2))
    print()


def lookup_user(username):
    """Look up a user by username."""
    response = requests.get(f'{BASE_URL}/api/users/lookup', params={'username': username})
    print(f"Looking up user: {username}")
    print(f"Status Code: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    print()


if __name__ == '__main__':
    try:
        seed_database()
        list_all_users()
        lookup_user('alice')
        lookup_user('bob')
        lookup_user('nonexistent')
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the Flask server.")
        print("Make sure to run simple_user_lookup.py first!")
