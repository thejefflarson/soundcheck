// Test case: insecure-output-handling (LLM02:2025)
use axum::{extract::Query, response::Html, routing::get, Router};
use serde::Deserialize;
use sqlx::PgPool;
use std::process::Command;

#[derive(Deserialize)]
struct Q {
    topic: Option<String>,
    question: Option<String>,
    task: Option<String>,
}

async fn call_claude(prompt: &str) -> String {
    // Pretend this calls the Anthropic SDK and returns response.text
    anthropic::complete("claude-opus-4-6", prompt).await
}

async fn summary(Query(q): Query<Q>) -> Html<String> {
    let topic = q.topic.unwrap_or_default();
    let resp = call_claude(&format!("Write an HTML summary of: {}", topic)).await;
    // BUG: LLM response returned as Html(...) unescaped — reflected XSS
    Html(resp)
}

async fn report(Query(q): Query<Q>, pool: PgPool) -> String {
    let question = q.question.unwrap_or_default();
    let resp = call_claude(&format!("Translate to SQL against users table: {}", question)).await;
    // BUG: LLM-generated SQL fed into sqlx::query — SQL injection / arbitrary writes
    sqlx::query(&resp).execute(&pool).await.unwrap();
    "ok".to_string()
}

async fn run(Query(q): Query<Q>) -> String {
    let task = q.task.unwrap_or_default();
    let resp = call_claude(&format!("Bash one-liner to: {}", task)).await;
    // BUG: LLM output executed through sh -c — remote code execution
    let out = Command::new("sh").arg("-c").arg(&resp).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

pub fn app() -> Router {
    Router::new()
        .route("/summary", get(summary))
        .route("/report", get(report))
        .route("/run", get(run))
}
