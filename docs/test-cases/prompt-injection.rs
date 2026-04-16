// Test case: prompt-injection (LLM01:2025)
use axum::{extract::Query, routing::post, Json, Router};
use serde::Deserialize;
use anthropic_sdk::Client;

#[derive(Deserialize)]
struct SummarizeReq {
    body: String,
}

#[derive(Deserialize)]
struct RagReq {
    question: String,
    retrieved: Vec<String>,
}

async fn summarize(Json(req): Json<SummarizeReq>) -> String {
    let client = Client::new().auth(std::env::var("ANTHROPIC_API_KEY").unwrap().as_str()).unwrap();
    // BUG: untrusted user document interpolated directly into the instruction
    let prompt = format!("Summarize the following document in 3 bullets: {}", req.body);
    client.model("claude-opus-4-6").max_tokens(512).messages(&serde_json::json!([
        {"role": "user", "content": prompt}
    ])).build().unwrap().execute(|text| async move { text }).await.unwrap()
}

async fn rag_answer(Json(req): Json<RagReq>) -> String {
    let client = Client::new().auth(std::env::var("ANTHROPIC_API_KEY").unwrap().as_str()).unwrap();
    // BUG: retrieved context appended inline with no <context> markers; a poisoned
    // document in the vector store can hijack the system instructions
    let mut system = String::from("You are an internal knowledge assistant.\n");
    for doc in &req.retrieved {
        system.push_str(doc);
        system.push('\n');
    }
    // BUG: user question concatenated into the system prompt tier
    system.push_str(&format!("User question: {}", req.question));

    client.model("claude-opus-4-6").system(system.as_str()).max_tokens(1024)
        .messages(&serde_json::json!([{"role": "user", "content": "Answer please."}]))
        .build().unwrap().execute(|text| async move { text }).await.unwrap()
}

async fn translate(Query(q): Query<std::collections::HashMap<String, String>>) -> String {
    let client = Client::new().auth(std::env::var("ANTHROPIC_API_KEY").unwrap().as_str()).unwrap();
    let input = q.get("text").cloned().unwrap_or_default();
    // BUG: query-string input spliced into an instruction with no validation
    let prompt = format!("Translate to French, preserving tone: {}", input);
    client.model("claude-opus-4-6").max_tokens(256)
        .messages(&serde_json::json!([{"role": "user", "content": prompt}]))
        .build().unwrap().execute(|text| async move { text }).await.unwrap()
}

pub fn router() -> Router {
    Router::new()
        .route("/summarize", post(summarize))
        .route("/rag", post(rag_answer))
        .route("/translate", post(translate))
}
