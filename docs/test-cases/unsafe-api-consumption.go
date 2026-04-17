// Unsafe API consumption — intentionally vulnerable. DO NOT deploy.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
)

var db *sql.DB

type PartnerProduct struct {
	Name  string `json:"name"`
	Price string `json:"price"`
}

// BUG: external API data concatenated into SQL
func syncProducts(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get("https://api.partner.com/products")
	defer resp.Body.Close()
	var products []PartnerProduct
	json.NewDecoder(resp.Body).Decode(&products) // no size limit
	for _, p := range products {
		// SQL injection via compromised partner API
		query := fmt.Sprintf("INSERT INTO products (name, price) VALUES ('%s', '%s')", p.Name, p.Price)
		db.Exec(query)
	}
	fmt.Fprint(w, "synced")
}

// BUG: rendering external content as trusted HTML
func embedWidget(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get("https://api.widgets.com/embed")
	defer resp.Body.Close()
	var data struct{ HTML string }
	json.NewDecoder(resp.Body).Decode(&data)
	// template.HTML marks string as safe — XSS if widget API is compromised
	tmpl := template.Must(template.New("").Parse(`<div>{{.}}</div>`))
	tmpl.Execute(w, template.HTML(data.HTML))
}

func main() {
	http.HandleFunc("/sync", syncProducts)
	http.HandleFunc("/widget", embedWidget)
	http.ListenAndServe(":8080", nil)
}
