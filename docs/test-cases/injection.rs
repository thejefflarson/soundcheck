// Test case: injection (A05:2025)
use axum::{extract::Query, routing::get, Router};
use handlebars::Handlebars;
use serde::Deserialize;
use sqlx::PgPool;
use std::process::Command;

#[derive(Deserialize)]
struct UserQuery { id: String }

async fn get_user(Query(q): Query<UserQuery>, pool: PgPool) -> String {
    // BUG: SQL injection — user input format!()'d into the query string
    let sql = format!("SELECT name FROM users WHERE id = {}", q.id);
    let row: (String,) = sqlx::query_as(&sql).fetch_one(&pool).await.unwrap();
    row.0
}

#[derive(Deserialize)]
struct FileQuery { filename: String }

async fn convert_file(Query(q): Query<FileQuery>) -> String {
    // BUG: shell injection — user input passed through sh -c
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("convert {} out.png", q.filename))
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[derive(Deserialize)]
struct GreetQuery { name: String }

async fn greet(Query(q): Query<GreetQuery>) -> String {
    let hb = Handlebars::new();
    // BUG: server-side template injection — user input rendered as a Handlebars template
    hb.render_template(&format!("Hello {}!", q.name), &()).unwrap()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/users", get(get_user))
        .route("/convert", get(convert_file))
        .route("/greet", get(greet));
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service()).await.unwrap();
}
