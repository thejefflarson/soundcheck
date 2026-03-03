# Test case: multi-agent-trust (LLM08:2025)
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

WORKER_URL = "http://worker-agent:8080"
ORCHESTRATOR_API_KEY = "sk-prod-abc123"


def run_research(topic: str) -> dict:
    # BUG: no auth token on inter-agent call
    resp = requests.post(f"{WORKER_URL}/research", json={"topic": topic})
    return resp.json()


def run_writer(research: dict) -> str:
    # BUG: passing full orchestrator API key to worker
    resp = requests.post(
        f"{WORKER_URL}/write",
        json={"research": research, "api_key": ORCHESTRATOR_API_KEY},
    )
    result = resp.json()
    # BUG: blindly executing worker output with no schema validation
    return result["output"]


@app.route("/pipeline")
def pipeline():
    topic = request.args.get("topic")
    research = run_research(topic)
    article = run_writer(research)
    return jsonify({"article": article})
