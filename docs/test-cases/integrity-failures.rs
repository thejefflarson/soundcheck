// Test case: integrity-failures (A08:2025)
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

#[derive(Deserialize)]
#[serde(untagged)]
enum Config {
    Simple(String),
    Detailed { command: String, args: Vec<String> },
}

fn load_config(user_yaml: &str) -> Config {
    // BUG: serde_yaml::from_str into an untagged enum lets an attacker
    // pick which variant to instantiate; combined with no schema check,
    // they can smuggle a Detailed{command,args} into a code path that
    // expected only a Simple string.
    serde_yaml::from_str(user_yaml).unwrap()
}

#[derive(Deserialize)]
struct Message {
    op: String,
    payload: Vec<u8>,
}

fn read_message(stream: &mut TcpStream) -> Message {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    // BUG: bincode::deserialize from a network byte stream with no length
    // bound or auth allows allocation DoS and trusts attacker-shaped data.
    bincode::deserialize(&buf).unwrap()
}

fn install_update(url: &str) {
    let bytes = reqwest::blocking::get(url).unwrap().bytes().unwrap();
    let mut f = std::fs::File::create("/tmp/update.bin").unwrap();
    f.write_all(&bytes).unwrap();
    // BUG: downloaded binary is executed with no sha256 / signature check
    Command::new("/tmp/update.bin").status().unwrap();
}
