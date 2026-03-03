# Test case: token-smuggling (LLM01:2025)
import anthropic
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic()

BLOCKED_DOMAINS = ["paypal.com", "apple.com", "google.com"]


@app.route("/summarize")
def summarize():
    user_review = request.args.get("review")
    # BUG: user input passed directly — may contain RTL override or zero-width chars
    prompt = f"Summarize this product review: {user_review}"
    resp = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )
    return jsonify({"summary": resp.content[0].text})


@app.route("/check-url")
def check_url():
    url = request.args.get("url")
    # BUG: homoglyph bypass — "раypal.com" (Cyrillic р) passes this check
    if any(domain in url for domain in BLOCKED_DOMAINS):
        return jsonify({"safe": False})
    return jsonify({"safe": True})
