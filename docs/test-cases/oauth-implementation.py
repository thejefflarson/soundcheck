# Test case: oauth-implementation (A07:2025)
import jwt
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = "hardcoded_flask_secret"

TRUSTED_BASE = "https://example.com"


@app.route("/oauth/start")
def oauth_start():
    # BUG: no state parameter — CSRF against OAuth callback possible
    redirect_uri = request.args.get("redirect_uri", "")
    return redirect(
        f"https://idp.example.com/auth?redirect_uri={redirect_uri}&client_id=myapp"
    )


@app.route("/oauth/callback")
def oauth_callback():
    # BUG: prefix match — "https://example.com.evil.com/steal" passes this check
    redirect_uri = request.args.get("redirect_uri", "")
    if not redirect_uri.startswith(TRUSTED_BASE):
        return "Bad redirect", 400

    # BUG: no state validation — no CSRF protection
    code = request.args.get("code")
    token = exchange_code(code, redirect_uri)

    # BUG: algorithms=["none"] accepts unsigned tokens; no audience check
    payload = jwt.decode(token, "secret", algorithms=["none", "HS256"])
    session["user_id"] = payload["sub"]
    return redirect(redirect_uri)


def exchange_code(code: str, redirect_uri: str) -> str:
    # BUG: redirect_uri passed verbatim — no exact-match validation
    import requests
    resp = requests.post("https://idp.example.com/token", data={
        "code": code,
        "redirect_uri": redirect_uri,
        "client_secret": "hardcoded_client_secret_xyz",  # BUG: hardcoded
    })
    return resp.json()["access_token"]
