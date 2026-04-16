// Test case: security-misconfiguration (A05:2025)
use axum::{routing::get, Router};
use std::env;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

// BUG: hardcoded secret committed to source
const JWT_SECRET: &str = "supersecret-do-not-share";
const ADMIN_TOKEN: &str = "admin:hunter2";

async fn root() -> &'static str {
    "hello"
}

#[tokio::main]
async fn main() {
    // BUG: debug logging enabled by default leaks sensitive request data to stdout
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "debug");
    }
    tracing_subscriber::fmt::init();
    tracing::debug!("starting with secret={}", JWT_SECRET);

    // BUG: permissive CORS combined with credentials exposes authenticated endpoints to any origin
    let cors = CorsLayer::permissive().allow_credentials(true);

    let app = Router::new()
        .route("/", get(root))
        .route("/admin", get(|| async { ADMIN_TOKEN }))
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    // BUG: plaintext HTTP listener — no TLS termination configured
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
