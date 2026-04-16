// Test case: security-misconfiguration (A05:2025)
package main

import (
	"log"
	"net/http"
)

// BUG: hardcoded admin credentials committed to source
const (
	AdminUser     = "admin"
	AdminPassword = "changeme"
	APISecret     = "sk_test_EXAMPLE_DO_NOT_USE"
)

// BUG: debug flag enabled by default exposes verbose error output
var debug = true

func handler(w http.ResponseWriter, r *http.Request) {
	// BUG: wildcard CORS with credentials allows any origin to read authenticated responses
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	// BUG: no security headers (HSTS, X-Content-Type-Options, X-Frame-Options) set
	if debug {
		w.Write([]byte("debug: request from " + r.RemoteAddr + " secret=" + APISecret))
		return
	}
	w.Write([]byte("ok"))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	// BUG: plaintext HTTP — TLS disabled, credentials transit in the clear
	log.Fatal(srv.ListenAndServe())
}
