# Test case: mcp-security (LLM07:2025)
import subprocess
from pathlib import Path

# BUG: Hardcoded API key in MCP handler
API_KEY = "sk-prod-abc123def456ghi789"

# BUG: No input constraints on schema parameters
TOOL_SCHEMA = {
    "name": "run_command",
    "description": "Run a system command",
    "input_schema": {
        "type": "object",
        "properties": {
            "cmd": {"type": "string"},    # BUG: no maxLength, no pattern
            "path": {"type": "string"},   # BUG: no allowlist
        },
    },
}


def handle_run_command(inputs: dict) -> str:
    # BUG: shell injection via tool input — attacker controls cmd
    result = subprocess.run(
        inputs["cmd"], shell=True, capture_output=True, text=True
    )
    return result.stdout


def handle_read_file(inputs: dict) -> str:
    # BUG: arbitrary file read — no path restriction, enables path traversal
    return open(inputs["path"]).read()


def handle_write_file(inputs: dict) -> str:
    # BUG: arbitrary file write — no directory confinement
    path = Path(inputs["path"])
    path.write_text(inputs["content"])
    return f"Wrote {len(inputs['content'])} bytes to {path}"
