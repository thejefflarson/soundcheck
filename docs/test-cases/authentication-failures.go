// Test case: authentication-failures (A07:2025)
package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("secret")

// BUG: MD5 used for password hashing (fast, broken, unsalted)
func hashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	stored := lookupHash(username)
	candidate := hashPassword(password)

	// BUG: timing-unsafe string comparison via == leaks hash bytes
	if stored != candidate {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	// BUG: session ID from math/rand.Intn — predictable, not crypto/rand
	sessionID := rand.Intn(1 << 30)
	fmt.Fprintf(w, "session=%d", sessionID)
}

func verifyToken(tokenStr string) (*jwt.Token, error) {
	// BUG: keyfunc returns secret without checking token.Method — accepts alg:none
	return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
}

func lookupHash(username string) string { return "" }

func main() { http.HandleFunc("/login", loginHandler); http.ListenAndServe(":8080", nil) }
