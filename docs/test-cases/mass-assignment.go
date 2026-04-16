// Test case: mass-assignment (API8:2023)
// GORM example of mass assignment from decoded JSON
package main

import (
	"encoding/json"
	"net/http"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`      // privileged field
	IsAdmin  bool   `json:"is_admin"`  // privileged field
}

func CreateUser(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		// BUG: decoding full request body into the ORM model
		// attacker sends {"username":"joe","role":"admin","is_admin":true}
		json.NewDecoder(r.Body).Decode(&user)
		// BUG: all decoded fields including Role and IsAdmin are persisted
		db.Create(&user)
		w.WriteHeader(http.StatusCreated)
	}
}
