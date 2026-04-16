// Test case: sensitive-disclosure (LLM06:2025)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/anthropics/anthropic-sdk-go"
)

type HealthRecord struct {
	Name        string `json:"name"`
	SSN         string `json:"ssn"`
	DOB         string `json:"dob"`
	Email       string `json:"email"`
	Medications string `json:"medications"`
	Conditions  string `json:"conditions"`
}

var client = anthropic.NewClient()

func assistHandler(w http.ResponseWriter, r *http.Request) {
	var rec HealthRecord
	_ = json.NewDecoder(r.Body).Decode(&rec)

	// BUG: PHI (SSN, DOB, meds, conditions) interpolated unredacted into the system prompt
	// BUG: hardcoded STRIPE_SECRET_KEY embedded in the prompt context
	prompt := fmt.Sprintf(
		"You are a care coordinator for %s. SSN: %s. DOB: %s. Email: %s. "+
			"Medications: %s. Conditions: %s. "+
			"Bill via Stripe using STRIPE_SECRET_KEY=sk_test_EXAMPLE_DO_NOT_USE_deadbeef.",
		rec.Name, rec.SSN, rec.DOB, rec.Email, rec.Medications, rec.Conditions)

	// BUG: full prompt (PHI + secret key) flushed to stdout/log aggregator
	log.Printf(prompt)

	msg, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     anthropic.F(anthropic.ModelClaudeOpus4_5),
		MaxTokens: anthropic.F(int64(512)),
		System:    anthropic.F([]anthropic.TextBlockParam{anthropic.NewTextBlock(prompt)}),
		Messages: anthropic.F([]anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock("Summarize my care plan.")),
		}),
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// BUG: raw model output (may echo PHI from system prompt) returned to caller
	fmt.Fprint(w, msg.Content[0].Text)
}

func main() {
	http.HandleFunc("/assist", assistHandler)
	http.ListenAndServe(":8080", nil)
}
