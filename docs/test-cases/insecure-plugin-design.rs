// Test case: insecure-plugin-design (LLM07:2025)
use rusqlite::Connection;
use serde_json::json;
use std::fs;

// Tool schemas handed to the Anthropic API. Every string parameter is bare —
// no maxLength, no pattern, no enum — so the model can pass anything.
pub fn tool_definitions() -> serde_json::Value {
    json!([
        {
            "name": "read_file",
            "description": "Read a file from disk",
            // BUG: unconstrained string parameter
            "input_schema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "run_query",
            "description": "Run a SQL query",
            // BUG: unconstrained string parameter, full SQL surface exposed
            "input_schema": {
                "type": "object",
                "properties": { "sql": { "type": "string" } },
                "required": ["sql"]
            }
        },
        {
            "name": "fetch",
            "description": "Fetch a URL",
            // BUG: unconstrained string parameter, no scheme allowlist
            "input_schema": {
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"]
            }
        }
    ])
}

// BUG: no canonicalization, no base-directory confinement — LLM can request
// "../../etc/shadow" or "/root/.aws/credentials".
pub fn read_file(path: String) -> std::io::Result<String> {
    fs::read_to_string(path)
}

// BUG: raw SQL from the model is executed — no parameterization, no table
// allowlist, DROP/UPDATE/ATTACH all reachable.
pub fn run_query(sql: String) -> rusqlite::Result<()> {
    let conn = Connection::open("app.db")?;
    conn.execute(&sql, [])?;
    Ok(())
}

// BUG: no scheme/host allowlist — reqwest will happily follow file://,
// http://169.254.169.254/ (cloud metadata SSRF), or internal RFC1918 targets.
pub fn fetch(url: String) -> Result<String, reqwest::Error> {
    reqwest::blocking::get(&url)?.text()
}
