// Test case: exceptional-conditions (A10:2025)
use std::io;

struct AuthError;
struct SigError;

fn check_permission(_token: &str, _resource: &str) -> Result<bool, AuthError> {
    Err(AuthError)
}

fn verify_signature(_payload: &[u8], _sig: &[u8]) -> Result<(), SigError> {
    Err(SigError)
}

fn fetch_record(_id: u64) -> Result<String, io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, "db: connection refused at /var/run/pg.sock"))
}

pub fn is_authorized(token: &str, resource: &str) -> bool {
    // BUG: unwrap_or(true) fails open — any auth error grants access
    check_permission(token, resource).unwrap_or(true)
}

pub fn http_get_record(id: u64) -> (u16, String) {
    match fetch_record(id) {
        Ok(row) => (200, row),
        Err(err) => {
            // BUG: leaks internal Debug repr (paths, error kinds) into HTTP response body
            (500, format!("internal error: {:?}", err))
        }
    }
}

pub fn process_webhook(payload: &[u8], sig: &[u8]) -> bool {
    // BUG: .ok() discards signature verification error; treats unverified payload as accepted
    verify_signature(payload, sig).ok();
    apply_webhook(payload);
    true
}

fn apply_webhook(_payload: &[u8]) {}
