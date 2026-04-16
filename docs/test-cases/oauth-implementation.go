// Test case: oauth-implementation (A07:2025)
package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const trustedBase = "https://app.example.com"

var signingKey = []byte("hardcoded_hs256_secret")

func OAuthStart(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	// BUG: no `state` generated — callback cannot detect CSRF
	http.Redirect(w, r,
		"https://idp.example.com/auth?client_id=myapp&redirect_uri="+redirectURI,
		http.StatusFound)
}

func OAuthCallback(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	// BUG: HasPrefix lets "https://app.example.com.attacker.io/x" through
	if !strings.HasPrefix(redirectURI, trustedBase) {
		http.Error(w, "bad redirect", 400)
		return
	}

	tokenStr := r.URL.Query().Get("token")
	// BUG: Keyfunc never checks token.Method — alg:none and HS/RS confusion both pass
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil || !tok.Valid {
		http.Error(w, "bad token", 401)
		return
	}
	// BUG: no `aud` claim check, no `state` validated against session

	// BUG: token written to a cookie without Secure or HttpOnly — XSS-readable
	http.SetCookie(w, &http.Cookie{
		Name:  "access_token",
		Value: tokenStr,
		Path:  "/",
	})
	w.Write([]byte("ok"))
}
