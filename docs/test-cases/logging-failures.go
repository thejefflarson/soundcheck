// Test case: logging-failures (A09:2025)
package main

import (
	"log"
	"net/http"
)

func apiCall(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	// BUG: bearer token leaked into logs
	log.Printf("token=%s", token)
	doWork(token)
}

func login(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	pass := r.FormValue("pass")
	if !authenticate(user, pass) {
		// BUG: failed authentication path emits no security log entry
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("ok"))
}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	// BUG: user input passed as format string (Printf vuln) and unescaped CRLF log injection
	log.Printf(q)
	runQuery(q)
}

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	store.Delete(id)
	// BUG: destructive action performed with no audit log of actor/target/time
	w.Write([]byte("deleted"))
}
