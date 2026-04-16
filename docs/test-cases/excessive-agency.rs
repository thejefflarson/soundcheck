// Test case: excessive-agency (LLM08:2025)
use serde_json::{json, Value};
use std::fs;
use std::process::Command;

struct Agent {
    client: anthropic::Client,
    db: sqlx::PgPool,
}

impl Agent {
    fn tool_schemas() -> Vec<Value> {
        vec![
            json!({"name": "fs_write", "description": "Write bytes to any path",
                   "input_schema": {"type": "object",
                     "properties": {"path": {"type": "string"}, "data": {"type": "string"}}}}),
            json!({"name": "shell_exec", "description": "Execute a shell command",
                   "input_schema": {"type": "object",
                     "properties": {"cmd": {"type": "string"}}}}),
            json!({"name": "db_delete", "description": "Delete a row by id",
                   "input_schema": {"type": "object",
                     "properties": {"table": {"type": "string"}, "id": {"type": "integer"}}}}),
        ]
    }

    async fn dispatch(&self, name: &str, args: &Value) -> String {
        match name {
            "fs_write" => {
                // BUG: no path allowlist — LLM may overwrite ~/.ssh/authorized_keys or /etc
                let path = args["path"].as_str().unwrap();
                fs::write(path, args["data"].as_str().unwrap().as_bytes()).unwrap();
                "ok".into()
            }
            "shell_exec" => {
                // BUG: arbitrary Command::new("sh") driven by LLM output, no confirmation
                let out = Command::new("sh").arg("-c")
                    .arg(args["cmd"].as_str().unwrap()).output().unwrap();
                String::from_utf8_lossy(&out.stdout).into_owned()
            }
            "db_delete" => {
                // BUG: destructive DELETE with no human approval or audit trail
                let q = format!("DELETE FROM {} WHERE id = $1", args["table"].as_str().unwrap());
                sqlx::query(&q).bind(args["id"].as_i64()).execute(&self.db).await.unwrap();
                "deleted".into()
            }
            _ => String::new(),
        }
    }

    async fn run(&self, task: &str) {
        let mut msgs = vec![json!({"role": "user", "content": task})];
        // BUG: unbounded agent loop with no dry-run mode and no kill switch
        loop {
            let resp = self.client.messages(task, Self::tool_schemas()).await.unwrap();
            if resp.stop_reason == "end_turn" { return; }
            for block in resp.content.iter().filter(|b| b.ty == "tool_use") {
                self.dispatch(&block.name, &block.input).await;
                msgs.push(json!({"role": "assistant", "content": block}));
            }
        }
    }
}
