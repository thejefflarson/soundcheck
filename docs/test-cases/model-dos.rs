// Test case: model-dos (LLM04:2025)
use axum::{routing::post, Json, Router};
use anthropic_sdk::{Client, MessagesRequestBuilder};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct ChatRequest {
    user_id: String,
    message: String,
}

#[derive(Serialize)]
struct ChatResponse {
    reply: String,
}

async fn chat(Json(req): Json<ChatRequest>) -> Json<ChatResponse> {
    let client = Client::from_env().unwrap();

    // BUG: req.message has no length cap — axum's default body limit is
    // the only guard, and nothing trims the prompt before forwarding
    let _user = req.user_id;

    // BUG: no per-IP or per-key rate limit (e.g. tower_governor); a single
    // caller can hammer /chat and drain the Anthropic spend budget
    loop {
        let result = MessagesRequestBuilder::default()
            .model("claude-opus-4-5".to_string())
            // BUG: max_tokens omitted — responses run to the model ceiling,
            // and on any transient error we retry forever with no backoff
            .messages(vec![serde_json::json!({
                "role": "user",
                "content": req.message,
            })])
            .build()
            .unwrap()
            .send(&client)
            .await;

        match result {
            Ok(resp) => return Json(ChatResponse { reply: resp.content }),
            Err(_) => continue, // retry forever
        }
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/chat", post(chat));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
