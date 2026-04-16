// Test case: token-smuggling (LLM01:2025)
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

var blockedDomains = []string{"paypal.com", "apple.com", "google.com"}

type translateReq struct {
	Text string `json:"text"`
}

func translateHandler(w http.ResponseWriter, r *http.Request) {
	var body translateReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// BUG: body.Text is formatted into the prompt without unicode/norm.NFKC.
	// Homoglyph attacks (e.g. Cyrillic 'а' U+0430) pass through untouched.
	prompt := fmt.Sprintf("Translate: %s", body.Text)
	resp := callClaude("claude-haiku-4-5-20251001", prompt, 512)
	w.Write([]byte(resp))
}

func summarizeHandler(w http.ResponseWriter, r *http.Request) {
	review := r.URL.Query().Get("review")
	// BUG: no filter for RTL override (\u202E) or invisible chars (\u200B, \u200C, \uFEFF)
	// before they are embedded in the LLM prompt.
	prompt := fmt.Sprintf("Summarize this review: %s", review)
	resp := callClaude("claude-haiku-4-5-20251001", prompt, 256)
	w.Write([]byte(resp))
}

func checkURLHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// BUG: blocklist check runs on raw bytes with no NFKC normalization.
	// "раypal.com" (Cyrillic р) trivially bypasses strings.Contains.
	for _, d := range blockedDomains {
		if strings.Contains(url, d) {
			w.Write([]byte(`{"safe":false}`))
			return
		}
	}
	w.Write([]byte(`{"safe":true}`))
}

func callClaude(model, prompt string, maxTokens int) string { return "" }

func main() {
	http.HandleFunc("/translate", translateHandler)
	http.HandleFunc("/summarize", summarizeHandler)
	http.HandleFunc("/check-url", checkURLHandler)
	http.ListenAndServe(":8080", nil)
}
