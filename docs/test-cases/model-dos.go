// Test case: model-dos (LLM04:2025)
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/anthropics/anthropic-sdk-go"
)

var client = anthropic.NewClient()

type chatRequest struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	// BUG: no MaxBytesReader on r.Body and no length check on Message —
	// a caller can POST a multi-gigabyte prompt and we'll forward it
	_ = json.NewDecoder(r.Body).Decode(&req)

	// BUG: no rate limiter (golang.org/x/time/rate) per IP or per API key;
	// a single client can flood /chat and exhaust token budget
	for {
		resp, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
			Model: anthropic.F(anthropic.ModelClaudeOpus4_5),
			// BUG: MaxTokens not set — responses run to model limit, and
			// on transient errors we retry forever with no backoff or cap
			Messages: anthropic.F([]anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(req.Message)),
			}),
		})
		if err != nil {
			continue // retry forever
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"reply": resp.Content[0].Text})
		return
	}
}

func main() {
	http.HandleFunc("/chat", chatHandler)
	http.ListenAndServe(":8080", nil)
}
