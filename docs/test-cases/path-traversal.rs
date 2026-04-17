// Path traversal — intentionally vulnerable. DO NOT deploy.
use actix_web::{get, web, App, HttpResponse, HttpServer};
use std::fs;

const UPLOAD_DIR: &str = "/app/uploads";

// BUG: format! with user input allows traversal
#[get("/download")]
async fn download(query: web::Query<FileQuery>) -> HttpResponse {
    let path = format!("{}/{}", UPLOAD_DIR, query.file);
    // No canonicalization — ../../etc/passwd works
    match fs::read(&path) {
        Ok(data) => HttpResponse::Ok().body(data),
        Err(e) => HttpResponse::NotFound().body(e.to_string()),
    }
}

// BUG: Path::join doesn't prevent absolute paths on all platforms
#[get("/read")]
async fn read_file(query: web::Query<FileQuery>) -> HttpResponse {
    let path = std::path::Path::new(UPLOAD_DIR).join(&query.file);
    // No containment check after join
    match fs::read_to_string(&path) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct FileQuery {
    file: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(download).service(read_file))
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
