// Test case: broken-access-control (A01:2025)
// net/http handlers with IDOR, env-flag admin gate, and SSRF.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

func getInvoice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/invoices/")
	// BUG: IDOR — fetches invoice by id with no check that the
	// authenticated caller actually owns it.
	inv, _ := db.QueryRow("SELECT * FROM invoices WHERE id = ?", id)
	json.NewEncoder(w).Encode(inv)
}

func adminPurge(w http.ResponseWriter, r *http.Request) {
	// BUG: admin route gated only by an env flag toggle, not by the
	// caller's role. Anyone who can reach the route on a server with
	// ADMIN_ENABLED=1 can purge data.
	if os.Getenv("ADMIN_ENABLED") != "1" {
		http.Error(w, "disabled", 403)
		return
	}
	db.Exec("DELETE FROM users")
	w.Write([]byte("ok"))
}

func fetchPreview(w http.ResponseWriter, r *http.Request) {
	userURL := r.URL.Query().Get("url")
	// BUG: SSRF — http.Get on caller-supplied URL with no allowlist.
	resp, err := http.Get(userURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Write(body)
}

func main() {
	http.HandleFunc("/invoices/", getInvoice)
	http.HandleFunc("/admin/purge", adminPurge)
	http.HandleFunc("/preview", fetchPreview)
	http.ListenAndServe(":8080", nil)
}
