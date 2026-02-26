# Test case: prompt-injection (LLM01:2025)
import anthropic

client = anthropic.Anthropic()

def answer_question(user_question, retrieved_docs):
    # BUG: user input and retrieved docs concatenated directly into system prompt
    system = f"""You are a helpful assistant with access to company documents.

    Context from documents:
    {retrieved_docs}

    The user asked: {user_question}

    Answer based on the documents above."""

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": "Please help me."}]
    )
    return response.content[0].text

def chat_with_email(email_content, user_instruction):
    # BUG: email content (external, attacker-controlled) mixed with instructions
    prompt = f"User wants you to: {user_instruction}\n\nEmail content:\n{email_content}"
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text
