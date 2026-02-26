# Test case: llm-supply-chain (LLM05:2025)
from transformers import AutoModelForCausalLM, AutoTokenizer
import urllib.request

def load_model():
    model_name = "some-org/some-model"

    # BUG: "main" is not a pinned revision — it moves with new commits
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        revision="main"
    )
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    return model, tokenizer

def download_model_weights(url):
    # BUG: downloads without hash verification — no integrity check
    urllib.request.urlretrieve(url, "model_weights.bin")
    return "model_weights.bin"
