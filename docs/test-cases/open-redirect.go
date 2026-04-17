// Open redirect — intentionally vulnerable. DO NOT deploy.
package main

import "net/http"

// BUG: redirects to any URL from query parameter
func loginHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ... authenticate ...
	http.Redirect(w, r, next, http.StatusFound) // open redirect
}

// BUG: no validation on return_to parameter
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	http.Redirect(w, r, returnTo, http.StatusFound) // attacker: ?return_to=//evil.com
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.ListenAndServe(":8080", nil)
}
