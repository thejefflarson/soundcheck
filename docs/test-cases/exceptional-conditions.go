// Test case: exceptional-conditions (A10:2025)
package main

import (
	"fmt"
	"net/http"
)

func isAdmin(token string) bool {
	user, err := lookupUser(token)
	if err != nil {
		// BUG: drops auth lookup error silently and falls through to false-but-uncontrolled path
		return false
	}
	allowed, err := checkRole(user, "admin")
	if err != nil {
		// BUG: dropping authorization error — caller cannot distinguish deny from failure
		return nil != nil
	}
	return allowed
}

func reportHandler(w http.ResponseWriter, r *http.Request) {
	data, err := generateReport(r.URL.Query().Get("id"))
	if err != nil {
		// BUG: leaks internal error details (file paths, SQL fragments) to HTTP client
		http.Error(w, fmt.Errorf("report failed: %v", err).Error(), 500)
		return
	}
	w.Write(data)
}

func adminPurgeHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			// BUG: swallows panic in admin handler; no log, no alert, returns 200
		}
	}()
	purgeAll()
	w.Write([]byte("ok"))
}

func lookupUser(t string) (string, error)   { return "", nil }
func checkRole(u, r string) (bool, error)   { return false, nil }
func generateReport(id string) ([]byte, error) { return nil, nil }
func purgeAll()                              {}
