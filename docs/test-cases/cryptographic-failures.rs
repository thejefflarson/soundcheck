// Test case: cryptographic-failures (A02:2025)
use md5::{Digest, Md5};
use rand::Rng;

// BUG: hardcoded encryption key bytes committed to source
const ENCRYPTION_KEY: [u8; 16] = [
    0x68, 0x61, 0x72, 0x64, 0x63, 0x6f, 0x64, 0x65,
    0x64, 0x6b, 0x65, 0x79, 0x31, 0x32, 0x33, 0x34,
];

pub fn hash_password(password: &str) -> String {
    // BUG: MD5 is broken and unsalted — use argon2 or bcrypt
    let mut hasher = Md5::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn generate_api_secret() -> String {
    // BUG: rand::random() uses ThreadRng — for secrets use OsRng / getrandom
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn weak_session_id() -> u64 {
    // BUG: thread_rng is not guaranteed cryptographic — use OsRng for tokens
    let mut rng = rand::thread_rng();
    rng.gen::<u64>()
}

pub fn encrypt_ecb(plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes128;
    let cipher = Aes128::new(GenericArray::from_slice(&ENCRYPTION_KEY));
    let mut block = GenericArray::clone_from_slice(&plaintext[..16]);
    // BUG: raw single-block AES with no mode == ECB; leaks patterns, no integrity
    cipher.encrypt_block(&mut block);
    block.to_vec()
}
