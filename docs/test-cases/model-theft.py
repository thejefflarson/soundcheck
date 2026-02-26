# Test case: model-theft (LLM10:2025)
import anthropic
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic()

# BUG: no authentication on inference endpoint — open to anyone
@app.route("/inference", methods=["POST"])
def inference():
    prompt = request.json.get("prompt")

    # BUG: no rate limiting, no user identification — enables extraction attacks
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2048,  # BUG: high token limit amplifies extraction
        messages=[{"role": "user", "content": prompt}]
    )

    return jsonify({
        "response": response.content[0].text,
        "model": "claude-opus-4-6",
        "tokens_used": response.usage.output_tokens,
        # BUG: exposes model name and token counts, aids extraction profiling
    })
