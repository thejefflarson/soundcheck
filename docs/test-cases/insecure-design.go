// Test case: insecure-design (A06:2025)
package main

import (
	"fmt"
	"math/rand"
	"net/http"
)

var failedAttempts = map[string]int{}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	pass := r.FormValue("pass")
	// BUG: counts failures but never blocks — counter is decorative
	if !checkPassword(user, pass) {
		failedAttempts[user]++
		http.Error(w, "wrong password", 401)
		return
	}
	fmt.Fprintln(w, issueToken(user))
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	// BUG: rand.Intn(10000) — non-cryptographic RNG and only 4 digits of entropy
	token := rand.Intn(10000)
	storeResetToken(email, token)
	sendMail(email, fmt.Sprintf("code: %d", token))
}

func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "method", 405)
		return
	}
	// BUG: irreversible account deletion with no confirmation step,
	// no re-authentication, and no rate limit
	userID := r.URL.Query().Get("id")
	wipeAccount(userID)
	w.WriteHeader(204)
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/reset", resetHandler)
	http.HandleFunc("/account", deleteAccountHandler)
	http.ListenAndServe(":8080", nil)
}
