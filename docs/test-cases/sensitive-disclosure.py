# Test case: sensitive-disclosure (LLM06:2025)
import anthropic

client = anthropic.Anthropic()

def personalize_response(user):
    # BUG: full user record with PII and secrets sent to LLM
    system = f"""You are a personal assistant for {user['name']}.
    Their email is {user['email']}, SSN is {user['ssn']},
    account balance is ${user['balance']}, medical conditions: {user['conditions']}.
    API key: {user['api_key']}"""

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=256,
        system=system,
        messages=[{"role": "user", "content": "What can you help me with?"}]
    )
    # BUG: returns raw LLM response that may echo back PII from system prompt
    return response.content[0].text

def debug_prompt(system_prompt):
    user_request = input("User: ")
    # BUG: exposes full system prompt to users on request
    if "show system prompt" in user_request.lower():
        return f"System prompt: {system_prompt}"
