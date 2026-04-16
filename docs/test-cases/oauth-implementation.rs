// Test case: oauth-implementation (A07:2025)
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

const TRUSTED_BASE: &str = "https://app.example.com";
const SIGNING_KEY: &[u8] = b"hardcoded_hs256_secret";

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn oauth_start(redirect_uri: &str) -> String {
    // BUG: no `state` or `nonce` generated — CSRF against OAuth callback
    format!(
        "https://idp.example.com/auth?client_id=myapp&redirect_uri={}",
        redirect_uri
    )
}

fn oauth_callback(redirect_uri: &str, token: &str) -> Result<String, String> {
    // BUG: starts_with prefix match — "https://app.example.com.attacker.io" passes
    if !redirect_uri.starts_with(TRUSTED_BASE) {
        return Err("bad redirect".into());
    }

    // BUG: Algorithm::None accepts unsigned tokens — full signature bypass
    let mut validation = Validation::new(Algorithm::None);
    validation.insecure_disable_signature_validation();
    // BUG: no audience set on the validation — wrong-aud tokens accepted
    validation.validate_aud = false;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SIGNING_KEY),
        &validation,
    )
    .map_err(|e| e.to_string())?;

    // BUG: no `state` parameter checked against stored session value
    Ok(format!("welcome {}", data.claims.sub))
}
