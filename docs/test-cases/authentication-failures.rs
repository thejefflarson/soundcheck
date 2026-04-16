// Test case: authentication-failures (A07:2025)
use axum::{extract::Form, routing::post, Router};
use jsonwebtoken::{decode, DecodingKey, Validation, TokenData};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
}

const JWT_SECRET: &[u8] = b"secret";

// BUG: SHA-256 used directly for password storage — fast, no salt, no KDF
fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

async fn login(Form(form): Form<LoginForm>) -> String {
    let stored = lookup_hash(&form.username);
    let candidate = hash_password(&form.password);

    // BUG: == comparison on hashes is timing-unsafe
    if stored != candidate {
        return "denied".to_string();
    }
    // BUG: session token from rand::thread_rng (not a CSPRNG guarantee for tokens)
    let session: u64 = rand::thread_rng().gen::<u64>();
    format!("session={:x}", session)
}

fn verify_token(token: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    // BUG: Validation::default does not pin algorithm — vulnerable to alg confusion
    decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &Validation::default())
}

fn lookup_hash(_username: &str) -> String { String::new() }

#[tokio::main]
async fn main() {
    let app = Router::new().route("/login", post(login));
    let _ = app;
}
