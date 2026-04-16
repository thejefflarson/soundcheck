// Test case: excessive-agency (LLM08:2025)
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"

	"github.com/anthropics/anthropic-sdk-go"
)

var db *sql.DB

func tools() []anthropic.ToolParam {
	return []anthropic.ToolParam{
		{Name: "execute_shell", Description: "Run any shell command",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"cmd": map[string]any{"type": "string"}}}},
		{Name: "write_file", Description: "Write content to any path",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"path": map[string]any{"type": "string"}, "data": map[string]any{"type": "string"}}}},
		{Name: "delete_record", Description: "Delete a DB row by id",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"table": map[string]any{"type": "string"}, "id": map[string]any{"type": "integer"}}}},
	}
}

func dispatch(name string, args map[string]any) string {
	switch name {
	case "execute_shell":
		// BUG: LLM-driven arbitrary command execution, no allowlist or confirmation
		out, _ := exec.Command("sh", "-c", args["cmd"].(string)).CombinedOutput()
		return string(out)
	case "write_file":
		// BUG: no path allowlist — agent can clobber system files or SSH keys
		_ = os.WriteFile(args["path"].(string), []byte(args["data"].(string)), 0644)
		return "ok"
	case "delete_record":
		// BUG: irreversible DELETE executed immediately on LLM instruction
		_, _ = db.Exec("DELETE FROM "+args["table"].(string)+" WHERE id = $1", args["id"])
		return "deleted"
	}
	return ""
}

func runAgent(ctx context.Context, client *anthropic.Client, task string) {
	msgs := []anthropic.MessageParam{{Role: "user", Content: task}}
	// BUG: loops until the LLM decides to stop — no human-in-the-loop, no audit log, no kill switch
	for {
		resp, _ := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model: "claude-opus-4-6", MaxTokens: 2048, Tools: tools(), Messages: msgs})
		if resp.StopReason == "end_turn" {
			return
		}
		for _, block := range resp.Content {
			if block.Type == "tool_use" {
				var in map[string]any
				_ = json.Unmarshal(block.Input, &in)
				dispatch(block.Name, in)
			}
		}
	}
}
