// Test case: overreliance (LLM09:2025)
package overreliance

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
)

var client = anthropic.NewClient()

func ask(prompt string) string {
	msg, _ := client.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     anthropic.F(anthropic.ModelClaudeOpus4_5),
		MaxTokens: anthropic.F(int64(512)),
		Messages: anthropic.F([]anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		}),
	})
	return msg.Content[0].Text
}

func HandleRefund(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("order_id")
	verdict := ask("Should we refund order " + orderID + "?")
	// BUG: refund (money movement) issued automatically from LLM verdict with no human approval
	if strings.Contains(strings.ToLower(verdict), "refund") {
		IssueRefund(orderID)
	}
}

func SummarizeContract(w http.ResponseWriter, contractText string) {
	summary := ask("Summarize this contract for a client: " + contractText)
	// BUG: LLM legal summary returned to end users as authoritative advice, no attorney review, no disclaimer
	fmt.Fprintf(w, `{"legal_summary": %q, "authoritative": true}`, summary)
}

func ComplianceGate(transaction string) bool {
	verdict := ask("Reply exactly OK or NOT OK: is this transaction compliant? " + transaction)
	// BUG: SOX/AML compliance gate decided by brittle LLM string match, no auditor review
	return strings.TrimSpace(verdict) == "OK"
}

func IssueRefund(orderID string) {}
