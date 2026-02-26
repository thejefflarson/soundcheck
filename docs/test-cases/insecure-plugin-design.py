# Test case: insecure-plugin-design (LLM07:2025)
import anthropic
import subprocess

client = anthropic.Anthropic()

# BUG: tool accepts any shell command, no validation or constraints
tools = [{
    "name": "run_command",
    "description": "Execute a system command",
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {"type": "string"}  # BUG: no maxLength, no pattern allowlist
        },
        "required": ["command"]
    }
}]

def handle_tool_call(tool_name, tool_input):
    if tool_name == "run_command":
        # BUG: no authorization check, no command validation, shell=True
        result = subprocess.run(tool_input["command"], shell=True, capture_output=True)
        return result.stdout.decode()

def read_file_tool(filename):
    # BUG: no path confinement — can read /etc/passwd, ~/.ssh/id_rsa, etc.
    with open(filename) as f:
        return f.read()
