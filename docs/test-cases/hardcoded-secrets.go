// Hardcoded secrets — intentionally vulnerable. DO NOT deploy.
package main

import "net/http"

// BUG: API key hardcoded in source
const apiKey = "sk-proj-EXAMPLE_DO_NOT_USE_abcdef123456"

// BUG: database credentials in source
const dbConnStr = "postgres://admin:supersecret@db.internal:5432/prod"

// BUG: JWT signing secret hardcoded
var jwtSecret = []byte("my-super-secret-jwt-key-do-not-share")

func callAPI() {
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	http.DefaultClient.Do(req)
}
