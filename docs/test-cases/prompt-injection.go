// Test case: prompt-injection (LLM01:2025)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
)

var client = anthropic.NewClient()

func translateHandler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("text")
	// BUG: user input formatted straight into the instruction tier
	prompt := fmt.Sprintf("Translate the following to French: %s", userInput)
	resp, _ := client.Messages.New(r.Context(), anthropic.MessageNewParams{
		Model:     anthropic.F("claude-opus-4-6"),
		MaxTokens: anthropic.F(int64(512)),
		Messages: anthropic.F([]anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		}),
	})
	fmt.Fprint(w, resp.Content[0].Text)
}

func ragHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Question string   `json:"question"`
		Docs     []string `json:"docs"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	// BUG: retrieved documents concatenated into the system prompt with no
	// delimiter tags — indirect injection via poisoned vector store content
	system := "You are a support agent. Use this context:\n" + strings.Join(body.Docs, "\n")
	// BUG: user question also splatted into the system role
	system += "\nThe user's question is: " + body.Question

	resp, _ := client.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     anthropic.F("claude-opus-4-6"),
		MaxTokens: anthropic.F(int64(1024)),
		System:    anthropic.F([]anthropic.TextBlockParam{anthropic.NewTextBlock(system)}),
		Messages: anthropic.F([]anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock("Please answer.")),
		}),
	})
	fmt.Fprint(w, resp.Content[0].Text)
}
