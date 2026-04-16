// Test case: insecure-design (A06:2025)
use axum::{routing::post, Json, Router};
use rand::Rng;
use serde::Deserialize;

#[derive(Deserialize)]
struct LoginReq { user: String, pass: String }

#[derive(Deserialize)]
struct ResetReq { email: String }

#[derive(Deserialize)]
struct PurchaseReq { item_id: u64, amount_cents: u64 }

async fn login(Json(req): Json<LoginReq>) -> &'static str {
    // BUG: no rate limit, no lockout, no per-IP throttling on credential check
    if verify(&req.user, &req.pass) { "ok" } else { "bad" }
}

async fn reset(Json(req): Json<ResetReq>) -> String {
    // BUG: u16 reset token — max 65536 values, trivially brute-forceable
    let token: u16 = rand::thread_rng().gen();
    store_reset(&req.email, token);
    format!("sent {}", token)
}

async fn purchase(Json(req): Json<PurchaseReq>) -> &'static str {
    // BUG: no spending cap or daily limit on amount_cents
    // BUG: no confirmation step or re-authentication for an arbitrary-amount charge
    charge_card(req.item_id, req.amount_cents);
    "purchased"
}

fn verify(_u: &str, _p: &str) -> bool { true }
fn store_reset(_e: &str, _t: u16) {}
fn charge_card(_i: u64, _a: u64) {}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/login", post(login))
        .route("/reset", post(reset))
        .route("/purchase", post(purchase));
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service()).await.unwrap();
}
