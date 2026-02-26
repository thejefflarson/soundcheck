# Test case: overreliance (LLM09:2025)
import anthropic

client = anthropic.Anthropic()

def diagnose_symptoms(symptoms):
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=512,
        messages=[{"role": "user", "content": f"Patient symptoms: {symptoms}. What is the diagnosis?"}]
    )
    # BUG: presents LLM output as authoritative medical diagnosis, no disclaimer
    diagnosis = response.content[0].text
    return {"diagnosis": diagnosis, "confidence": "high", "requires_review": False}

def auto_deploy_code(pr_description):
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=256,
        messages=[{"role": "user", "content": f"Is this PR safe to deploy? {pr_description}"}]
    )
    # BUG: auto-deploys to production based solely on LLM judgment, no human gate
    if "safe" in response.content[0].text.lower():
        deploy_to_production()
