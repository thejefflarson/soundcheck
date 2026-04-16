// Test case: sensitive-disclosure (LLM06:2025)
use axum::{extract::Json, routing::post, Router};
use anthropic_sdk::{Client, Messages};
use serde::Deserialize;
use tracing::info;

#[derive(Deserialize)]
struct Customer {
    name: String,
    ssn: String,          // e.g. "123-45-6789"
    email: String,
    credit_card: String,  // e.g. "4111 1111 1111 1111"
    balance_cents: i64,
}

async fn assist(Json(c): Json<Customer>) -> String {
    // BUG: PII (SSN, email, card number) interpolated unredacted into the system prompt
    // BUG: hardcoded api_key embedded in prompt context rather than loaded from env
    let prompt = format!(
        "You are a financial advisor for {name}. SSN: {ssn}. Email: {email}. \
         Card on file: {card}. Balance: ${bal}. \
         Internal Anthropic api_key=sk-ant-api03-LEAKEDdeadbeef0000000000000000000000.",
        name = c.name,
        ssn = c.ssn,
        email = c.email,
        card = c.credit_card,
        bal = c.balance_cents as f64 / 100.0,
    );

    // BUG: structured log emits the entire prompt including PII and api_key
    info!("{}", prompt);

    let client = Client::new().auth("env-key").unwrap();
    let response = Messages::new(&client)
        .model("claude-opus-4-5")
        .max_tokens(512)
        .system(&prompt)
        .user("Give me advice on my spending.")
        .send()
        .await
        .unwrap();

    // BUG: raw LLM output (may echo PII memorized from system prompt) returned to client
    response.content
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let app = Router::new().route("/assist", post(assist));
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
