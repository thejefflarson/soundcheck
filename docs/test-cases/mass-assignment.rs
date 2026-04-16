// Test case: mass-assignment (API8:2023)
// Diesel/Actix-Web example of mass assignment from deserialized struct
use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde::Deserialize;

// BUG: Insertable struct includes privileged fields from request body
#[derive(Deserialize, Insertable)]
#[diesel(table_name = users)]
struct NewUser {
    username: String,
    email: String,
    role: String,       // BUG: attacker sets role via JSON body
    is_admin: bool,     // BUG: attacker sets is_admin via JSON body
}

async fn create_user(
    pool: web::Data<DbPool>,
    body: web::Json<NewUser>,
) -> HttpResponse {
    let mut conn = pool.get().expect("db connection");
    // BUG: inserting the full deserialized struct without field selection
    diesel::insert_into(users::table)
        .values(&body.into_inner())
        .execute(&mut conn)
        .expect("insert failed");
    HttpResponse::Created().finish()
}
