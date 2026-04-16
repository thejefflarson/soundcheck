// Test case: token-smuggling (LLM01:2025)
use axum::{extract::Query, routing::get, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

const BLOCKED_DOMAINS: &[&str] = &["paypal.com", "apple.com", "google.com"];

#[derive(Deserialize)]
struct SummarizeQ {
    text: String,
}

#[derive(Deserialize)]
struct UrlQ {
    url: String,
}

async fn summarize(Query(q): Query<SummarizeQ>) -> Json<Value> {
    // BUG: q.text is interpolated into the prompt with no
    // unicode_normalization::UnicodeNormalization::nfkc() pass. Homoglyphs
    // and compatibility forms reach the model unmodified.
    let prompt = format!("Summarize: {}", q.text);
    let out = call_claude("claude-haiku-4-5-20251001", &prompt, 256).await;
    Json(json!({ "summary": out }))
}

async fn translate(Query(q): Query<SummarizeQ>) -> Json<Value> {
    // BUG: no stripping of zero-width chars (\u{200B}, \u{200C}, \u{2060}, \u{FEFF})
    // or bidi overrides (\u{202E}) before prompt construction.
    let prompt = format!("Translate to English: {}", q.text);
    let out = call_claude("claude-haiku-4-5-20251001", &prompt, 512).await;
    Json(json!({ "translation": out }))
}

async fn check_url(Query(q): Query<UrlQ>) -> Json<Value> {
    // BUG: blocklist comparison on raw input — "раypal.com" (Cyrillic р, U+0440)
    // slips past contains() because the URL is never NFKC-normalized.
    for d in BLOCKED_DOMAINS {
        if q.url.contains(d) {
            return Json(json!({ "safe": false }));
        }
    }
    Json(json!({ "safe": true }))
}

async fn call_claude(_model: &str, _prompt: &str, _max_tokens: u32) -> String {
    String::new()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/summarize", get(summarize))
        .route("/translate", get(translate))
        .route("/check-url", get(check_url));
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
