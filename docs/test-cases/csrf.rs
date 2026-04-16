// Test case: csrf (A01:2025)
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};

// BUG: no CSRF middleware registered on the application
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/transfer", web::get().to(show_form))
            .route("/transfer", web::post().to(do_transfer))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn show_form() -> HttpResponse {
    // BUG: form has no CSRF token hidden field
    HttpResponse::Ok().content_type("text/html").body(r#"
        <form method="POST" action="/transfer">
            <input name="amount"/>
            <input name="to"/>
            <button>Send</button>
        </form>
    "#)
}

// BUG: state-changing endpoint accepts POST with no CSRF token validation
async fn do_transfer(req: HttpRequest, form: web::Form<TransferForm>) -> HttpResponse {
    execute_transfer(&form.amount, &form.to);
    HttpResponse::SeeOther()
        .insert_header(("Location", "/done"))
        .finish()
}

#[derive(serde::Deserialize)]
struct TransferForm {
    amount: String,
    to: String,
}

fn execute_transfer(amount: &str, to: &str) {}
