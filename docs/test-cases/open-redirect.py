"""Open redirect — intentionally vulnerable. DO NOT deploy."""
from flask import Flask, request, redirect

app = Flask(__name__)

# BUG: redirects to any URL the caller supplies
@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    # ... authenticate ...
    return redirect(next_url)  # attacker: /login?next=https://evil.com

# BUG: no validation on return URL
@app.route("/oauth/callback")
def oauth_callback():
    return_to = request.args.get("return_to")
    return redirect(return_to)  # open redirect via OAuth flow

# BUG: scheme-relative bypass
@app.route("/goto")
def goto():
    url = request.args.get("url")
    if not url.startswith("http://evil"):  # bypassed with //evil.com
        return redirect(url)
