// Test case: injection (A05:2025)
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"text/template"

	_ "github.com/lib/pq"
)

var db *sql.DB

func getUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	// BUG: SQL injection via fmt.Sprintf into db.Query
	rows, err := db.Query(fmt.Sprintf("SELECT name FROM users WHERE id = %s", userID))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func convertFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	// BUG: shell injection — user input passed to sh -c
	out, _ := exec.Command("sh", "-c", "convert "+filename+" out.png").CombinedOutput()
	w.Write(out)
}

func greet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// BUG: server-side template injection — user input compiled into a template
	t, _ := template.New("greet").Parse(fmt.Sprintf("Hello %s!", name))
	t.Execute(w, nil)
}

func main() {
	http.HandleFunc("/users", getUser)
	http.HandleFunc("/convert", convertFile)
	http.HandleFunc("/greet", greet)
	http.ListenAndServe(":8080", nil)
}
