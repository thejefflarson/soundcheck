// Test case: csrf (A01:2025)
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/transfer", transferHandler)
	http.ListenAndServe(":8080", nil)
}

// BUG: POST handler with no CSRF middleware protecting state-changing endpoint
func transferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// BUG: form rendered without CSRF token field
		fmt.Fprint(w, `<form method="POST" action="/transfer">
			<input name="amount"/>
			<input name="to"/>
			<button>Send</button>
		</form>`)
		return
	}
	r.ParseForm()
	amount := r.FormValue("amount")
	to := r.FormValue("to")
	executeTransfer(amount, to)

	// BUG: session cookie set without SameSite attribute
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		HttpOnly: true,
	})
	http.Redirect(w, r, "/done", http.StatusSeeOther)
}

func executeTransfer(amount, to string) {}
