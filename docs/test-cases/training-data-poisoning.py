# Test case: training-data-poisoning (LLM03:2025)
import json
import requests

def collect_training_data():
    # BUG: scrapes from user-controllable source with no validation
    response = requests.get("https://community-forum.example.com/posts/export")
    examples = response.json()

    # BUG: no content validation or filtering
    training_data = []
    for post in examples:
        training_data.append({
            "prompt": post["question"],
            "completion": post["answer"]
        })

    # BUG: no integrity check or provenance tracking
    with open("training_data.jsonl", "w") as f:
        for example in training_data:
            f.write(json.dumps(example) + "\n")

    return training_data

def fine_tune_model(training_file):
    import openai
    # BUG: uploads unvalidated data directly to fine-tuning API
    with open(training_file, "rb") as f:
        uploaded = openai.files.create(file=f, purpose="fine-tune")
    openai.fine_tuning.jobs.create(
        training_file=uploaded.id,
        model="gpt-4o-mini"
    )
