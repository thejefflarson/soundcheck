// Test case: insecure-plugin-design (LLM07:2025)
package tools

import (
	"database/sql"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/anthropics/anthropic-sdk-go"
)

var db *sql.DB

// BUG: InputSchema declares every parameter as a bare {"type":"string"} with no
// maxLength, no pattern, no enum — the LLM can pass anything, including shell
// metacharacters, absolute paths, or file:// URLs.
var Tools = []anthropic.ToolParam{
	{
		Name:        anthropic.F("read_file"),
		Description: anthropic.F("Read a file"),
		InputSchema: anthropic.F(any(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"}, // BUG: unconstrained
			},
			"required": []string{"path"},
		})),
	},
	{
		Name:        anthropic.F("run_command"),
		Description: anthropic.F("Run a shell command"),
		InputSchema: anthropic.F(any(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{"type": "string"}, // BUG: no allowlist
			},
		})),
	},
	{
		Name:        anthropic.F("fetch"),
		Description: anthropic.F("Fetch a URL"),
		InputSchema: anthropic.F(any(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url": map[string]any{"type": "string"}, // BUG: no scheme/host allowlist
			},
		})),
	},
}

// BUG: handler executes every tool with zero validation or authorization —
// path traversal, arbitrary shell exec, and SSRF all reachable from chat input.
func HandleTool(name string, input map[string]string) (string, error) {
	switch name {
	case "read_file":
		b, err := os.ReadFile(input["path"])
		return string(b), err
	case "run_command":
		out, err := exec.Command("sh", "-c", input["command"]).CombinedOutput()
		return string(out), err
	case "fetch":
		resp, err := http.Get(input["url"])
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	return "", nil
}
