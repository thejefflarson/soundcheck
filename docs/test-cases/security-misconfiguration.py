# Test case: security-misconfiguration (A02:2025)
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
# BUG: CORS wildcard allows any origin with credentials
CORS(app, origins="*", supports_credentials=True)

# BUG: hardcoded credentials
DATABASE_URL = "postgresql://admin:password123@localhost/prod"
SECRET_KEY = "mysecretkey"

# BUG: no security headers set
@app.after_request
def add_headers(response):
    return response  # returns nothing useful

if __name__ == "__main__":
    # BUG: debug mode enabled — exposes stack traces and interactive debugger
    app.run(debug=True, host="0.0.0.0")
