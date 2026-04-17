// HTTP header injection — intentionally vulnerable. DO NOT deploy.
package main

import (
	"fmt"
	"net/http"
)

// BUG: user input in Content-Disposition header — CRLF injection
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")
	// Attacker: name=file.txt%0d%0aX-Injected:%20true
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Write([]byte("file content"))
}

// BUG: forwarding request header to response without sanitization
func apiHandler(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-Id")
	// Attacker sends X-Request-Id with \r\n to inject headers
	w.Header().Set("X-Request-Id", requestID)
	w.Write([]byte(`{"ok": true}`))
}

func main() {
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/api", apiHandler)
	http.ListenAndServe(":8080", nil)
}
