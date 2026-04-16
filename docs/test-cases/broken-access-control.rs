// Test case: broken-access-control (A01:2025)
// axum handlers with IDOR, missing role gate, and SSRF.
use axum::{extract::{Path, Query, Extension}, routing::{get, delete}, Json, Router};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct Document { id: i64, owner_id: i64, body: String }

struct AuthUser { id: i64, is_admin: bool }

#[derive(Deserialize)]
struct PreviewParams { url: String }

// BUG: IDOR — loads document by path id without checking
// auth_user.id == record.owner_id. Any logged-in user can read any doc.
async fn get_document(
    Path(id): Path<i64>,
    Extension(_auth_user): Extension<AuthUser>,
    Extension(db): Extension<Db>,
) -> Json<Document> {
    let doc = db.fetch_document(id).await.unwrap();
    Json(doc)
}

// BUG: admin route with no role gate. is_admin on AuthUser is never checked.
async fn admin_delete_user(
    Path(uid): Path<i64>,
    Extension(_auth_user): Extension<AuthUser>,
    Extension(db): Extension<Db>,
) {
    db.delete_user(uid).await.unwrap();
}

// BUG: SSRF — reqwest::get on caller-supplied URL with no allowlist.
async fn preview(Query(p): Query<PreviewParams>) -> String {
    let resp = reqwest::get(&p.url).await.unwrap();
    resp.text().await.unwrap()
}

pub fn router() -> Router {
    Router::new()
        .route("/documents/:id", get(get_document))
        .route("/admin/users/:uid", delete(admin_delete_user))
        .route("/preview", get(preview))
}

// Stub types to keep the example self-contained.
#[derive(Clone)] struct Db;
impl Db {
    async fn fetch_document(&self, _id: i64) -> Result<Document, ()> { unimplemented!() }
    async fn delete_user(&self, _id: i64) -> Result<(), ()> { unimplemented!() }
}
