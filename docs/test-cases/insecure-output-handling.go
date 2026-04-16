// Test case: insecure-output-handling (LLM02:2025)
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

func callClaude(prompt string) string {
	// Pretend this calls the Anthropic SDK and returns the text body.
	return anthropicComplete("claude-opus-4-6", prompt)
}

func summaryHandler(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	aiHTML := callClaude("Write an HTML summary of: " + topic)

	// BUG: LLM response written as text/html with no escaping — reflected XSS
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>%s</body></html>", aiHTML)
}

func reportHandler(w http.ResponseWriter, r *http.Request) {
	question := r.URL.Query().Get("q")
	query := callClaude("Translate to SQL against users table: " + question)

	// BUG: LLM-generated SQL passed straight to db.Exec — SQL injection / destructive writes
	if _, err := db.Exec(query); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write([]byte("ok"))
}

func runHandler(w http.ResponseWriter, r *http.Request) {
	task := r.URL.Query().Get("task")
	cmd := callClaude("Bash one-liner to: " + task)

	// BUG: LLM output executed via sh -c — remote code execution
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	w.Write(out)
}
