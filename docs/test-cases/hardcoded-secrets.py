"""Hardcoded secrets — intentionally vulnerable. DO NOT deploy."""
import requests

# BUG: API key hardcoded in source
OPENAI_KEY = "sk-proj-EXAMPLE_DO_NOT_USE_abcdef123456"
STRIPE_KEY = "sk_test_EXAMPLE_DO_NOT_USE_deadbeef"

# BUG: database credentials in connection string
DB_URL = "postgresql://admin:supersecretpassword@db.internal:5432/prod"

# BUG: password hardcoded for admin bootstrap
ADMIN_PASSWORD = "changeme123!"

def call_openai(prompt: str) -> str:
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_KEY}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]},
    )
    return resp.json()["choices"][0]["message"]["content"]

def charge_customer(amount: int):
    requests.post(
        "https://api.stripe.com/v1/charges",
        auth=(STRIPE_KEY, ""),
        data={"amount": amount, "currency": "usd"},
    )
