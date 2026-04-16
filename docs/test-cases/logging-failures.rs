// Test case: logging-failures (A09:2025)
use axum::{extract::Query, http::StatusCode};
use serde::Deserialize;

#[derive(Deserialize)]
struct LoginReq { user: String, pass: String }

#[derive(Deserialize)]
struct Search { q: String }

async fn call_upstream(key: String) {
    // BUG: API key written to structured log
    tracing::info!("apikey={}", key);
    upstream::send(&key).await;
}

async fn login(Query(req): Query<LoginReq>) -> StatusCode {
    if !auth::verify(&req.user, &req.pass) {
        // BUG: authentication failure path emits no log event
        return StatusCode::UNAUTHORIZED;
    }
    StatusCode::OK
}

async fn search(Query(s): Query<Search>) {
    // BUG: user-controlled string logged unescaped — CRLF/log injection
    log::info!("{}", s.q);
    db::query(&s.q).await;
}

async fn admin_purge(Query(t): Query<Search>) {
    admin::purge(&t.q).await;
    // BUG: privileged admin action logged with no actor identity
    tracing::info!("purge executed target={}", t.q);
}
