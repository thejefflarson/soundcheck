// Unsafe API consumption — intentionally vulnerable. DO NOT deploy.
use actix_web::{get, App, HttpResponse, HttpServer};
use serde::Deserialize;

#[derive(Deserialize)]
struct PartnerProduct {
    name: String,
    price: String,
}

// BUG: external API data used in SQL via format string
#[get("/sync")]
async fn sync_products() -> HttpResponse {
    let resp = reqwest::get("https://api.partner.com/products")
        .await
        .unwrap();
    // No size limit on response body
    let products: Vec<PartnerProduct> = resp.json().await.unwrap();
    let pool = get_db_pool();
    for p in &products {
        // SQL injection via compromised partner API
        let query = format!(
            "INSERT INTO products (name, price) VALUES ('{}', '{}')",
            p.name, p.price
        );
        sqlx::query(&query).execute(&pool).await.unwrap();
    }
    HttpResponse::Ok().body("synced")
}

// BUG: external HTML rendered without sanitization
#[get("/widget")]
async fn embed_widget() -> HttpResponse {
    let resp = reqwest::get("https://api.widgets.com/embed")
        .await
        .unwrap();
    let body = resp.text().await.unwrap(); // could be malicious HTML
    // Returned as text/html — XSS via compromised widget API
    HttpResponse::Ok()
        .content_type("text/html")
        .body(format!("<div class='widget'>{}</div>", body))
}

fn get_db_pool() -> sqlx::PgPool {
    unimplemented!()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(sync_products).service(embed_widget))
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
