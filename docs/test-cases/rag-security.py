# Test case: rag-security (LLM01:2025)
import requests

SYSTEM_PROMPT = "You are a helpful assistant. Answer user questions accurately."


def retrieve_document(url: str) -> str:
    # BUG: arbitrary URL fetch — no domain allowlist, enables SSRF
    response = requests.get(url, timeout=30)
    # BUG: no content length limit — context flooding or token exhaustion
    return response.text


def build_prompt(user_query: str, doc_url: str) -> str:
    doc_content = retrieve_document(doc_url)
    # BUG: retrieved content injected directly into prompt without delimiter
    # An attacker can embed "Ignore previous instructions..." in the document
    prompt = f"{SYSTEM_PROMPT}\n\nContext:\n{doc_content}\n\nQuestion: {user_query}"
    return prompt


def answer_question(user_query: str, sources: list[str]) -> str:
    all_context = ""
    for url in sources:
        # BUG: no source validation — any URL accepted including internal services
        doc = retrieve_document(url)
        all_context += doc + "\n"  # BUG: unbounded accumulation

    # BUG: mixed context injected with no separation from system instructions
    full_prompt = SYSTEM_PROMPT + "\n" + all_context + "\nQ: " + user_query
    return full_prompt
