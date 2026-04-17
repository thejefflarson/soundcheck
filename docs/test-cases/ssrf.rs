// SSRF — intentionally vulnerable. DO NOT deploy.
use actix_web::{get, web, App, HttpResponse, HttpServer};

// BUG: fetches any URL the caller supplies
#[get("/preview")]
async fn preview(query: web::Query<PreviewQuery>) -> HttpResponse {
    // No validation — attacker can reach http://169.254.169.254/
    let resp = reqwest::get(&query.url).await.unwrap();
    let body = resp.text().await.unwrap();
    HttpResponse::Ok().body(format!("Fetched: {}", &body[..500.min(body.len())]))
}

// BUG: proxy with no host validation or IP blocking
#[get("/proxy")]
async fn proxy(query: web::Query<ProxyQuery>) -> HttpResponse {
    // Attacker sends target=http://localhost:6379/ to probe internal services
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10)) // follows redirects
        .build()
        .unwrap();
    let resp = client.get(&query.target).send().await.unwrap();
    let body = resp.bytes().await.unwrap();
    HttpResponse::Ok().body(body)
}

#[derive(serde::Deserialize)]
struct PreviewQuery { url: String }

#[derive(serde::Deserialize)]
struct ProxyQuery { target: String }

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(preview).service(proxy))
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
