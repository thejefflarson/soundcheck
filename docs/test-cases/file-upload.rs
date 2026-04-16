// Test case: file-upload (A04:2025)
use actix_multipart::Multipart;
use actix_web::{web, App, HttpResponse, HttpServer};
use futures_util::StreamExt;
use std::io::Write;

// BUG: uploads stored in webroot
const UPLOAD_DIR: &str = "./static/uploads/";

async fn upload(mut payload: Multipart) -> HttpResponse {
    while let Some(Ok(mut field)) = payload.next().await {
        let content_disposition = field.content_disposition();
        // BUG: user-controlled filename used directly — path traversal possible
        // BUG: no extension allowlist — any file type accepted
        let filename = content_disposition
            .get_filename()
            .unwrap_or("unknown")
            .to_string();

        let path = format!("{}{}", UPLOAD_DIR, filename);
        // BUG: no file size limit — reads entire stream without cap
        let mut file = std::fs::File::create(&path).unwrap();
        while let Some(Ok(chunk)) = field.next().await {
            file.write_all(&chunk).unwrap();
        }
    }
    HttpResponse::Ok().body("Uploaded")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().route("/upload", web::post().to(upload)))
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
