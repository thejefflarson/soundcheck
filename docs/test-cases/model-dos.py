# Test case: model-dos (LLM04:2025)
import anthropic
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic()

conversation_history = {}

@app.route("/chat", methods=["POST"])
def chat():
    user_id = request.json.get("user_id")
    message = request.json.get("message")  # BUG: no length limit on input

    # BUG: conversation history grows unbounded — no context trimming
    if user_id not in conversation_history:
        conversation_history[user_id] = []
    conversation_history[user_id].append({"role": "user", "content": message})

    # BUG: no max_tokens, no rate limiting, no timeout
    response = client.messages.create(
        model="claude-opus-4-6",
        messages=conversation_history[user_id]
    )

    reply = response.content[0].text
    conversation_history[user_id].append({"role": "assistant", "content": reply})
    return jsonify({"reply": reply})
