// SSRF — intentionally vulnerable. DO NOT deploy.
package main

import (
	"fmt"
	"io"
	"net/http"
)

// BUG: fetches any URL the caller supplies
func previewHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// No validation — attacker can reach http://169.254.169.254/latest/meta-data/
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(w, "Status: %d\nBody: %s", resp.StatusCode, body[:500])
}

// BUG: proxy endpoint with no host validation
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	// Attacker sends target=http://localhost:6379/ to reach Redis
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/preview", previewHandler)
	http.HandleFunc("/proxy", proxyHandler)
	http.ListenAndServe(":8080", nil)
}
