// Test case: overreliance (LLM09:2025)
use anthropic_sdk::Client;

async fn ask(prompt: &str) -> String {
    let client = Client::new().auth(std::env::var("ANTHROPIC_API_KEY").unwrap().as_str());
    let resp = client
        .model("claude-opus-4-5")
        .max_tokens(512)
        .messages(&serde_json::json!([{"role": "user", "content": prompt}]))
        .execute(|r| async move { r })
        .await
        .unwrap();
    resp.content[0].text.clone()
}

pub async fn triage_patient(symptoms: &str) -> &'static str {
    let label = ask(&format!("Severity (low/med/high) for: {}", symptoms)).await;
    // BUG: medical triage routing decided solely by LLM severity label, no nurse/doctor review
    if label.to_lowercase().contains("high") {
        dispatch_ambulance();
        "ER"
    } else {
        "self-care"
    }
}

pub async fn review_employee(employee_id: u64, performance_notes: &str) {
    let summary = ask(&format!("Should we fire employee? Notes: {}", performance_notes)).await;
    // BUG: termination (irreversible HR action) triggered from LLM hiring summary with no HR/manager review
    if summary.to_lowercase().contains("terminate") {
        hr_system_fire(employee_id);
    }
}

pub async fn auto_merge_pr(pr_id: u64, diff: &str) {
    let verdict = ask(&format!("Review this diff and reply LGTM if safe: {}", diff)).await;
    // BUG: PR auto-merged to main based solely on LLM "LGTM" string, no human reviewer approval
    if verdict.contains("LGTM") {
        git_merge(pr_id);
        deploy_production();
    }
}

fn dispatch_ambulance() {}
fn hr_system_fire(_id: u64) {}
fn git_merge(_id: u64) {}
fn deploy_production() {}
