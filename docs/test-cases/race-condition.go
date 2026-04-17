// Race condition — intentionally vulnerable. DO NOT deploy.
package main

import (
	"database/sql"
	"os"
)

var db *sql.DB

// BUG: TOCTOU — file can be replaced between Stat and ReadFile
func readIfExists(path string) ([]byte, error) {
	if _, err := os.Stat(path); err == nil {
		return os.ReadFile(path) // race window: file changed after check
	}
	return nil, nil
}

// BUG: double-spend — read-modify-write without transaction isolation
func transfer(fromID, toID int, amount float64) error {
	var balance float64
	db.QueryRow("SELECT balance FROM accounts WHERE id = ?", fromID).Scan(&balance)
	if balance >= amount {
		// Another goroutine can read the same balance here
		db.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, fromID)
		db.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, toID)
	}
	return nil
}

// BUG: counter increment without atomicity
var counter int

func incrementCounter() {
	val := counter // read
	counter = val + 1 // write — lost update under concurrency
}
