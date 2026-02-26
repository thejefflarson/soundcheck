# Test case: excessive-agency (LLM08:2025)
import anthropic
import os

client = anthropic.Anthropic()

def autonomous_agent(task):
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": task}],
        tools=[
            {"name": "delete_file", "description": "Delete a file",
             "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "send_email", "description": "Send an email to anyone",
             "input_schema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
            {"name": "execute_sql", "description": "Run any SQL query",
             "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}}},
        ]
    )

    for content in response.content:
        if content.type == "tool_use":
            # BUG: executes all LLM-requested actions without any confirmation
            if content.name == "delete_file":
                os.remove(content.input["path"])       # BUG: irreversible, no confirmation
            elif content.name == "send_email":
                send_email(content.input["to"], content.input["body"])  # BUG: no approval
            elif content.name == "execute_sql":
                db.execute(content.input["query"])     # BUG: no validation/approval
