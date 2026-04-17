// Path traversal — intentionally vulnerable. DO NOT deploy.
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/app/uploads"

// BUG: filepath.Join does NOT prevent traversal — ../../etc/passwd works
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	path := filepath.Join(uploadDir, filename)
	data, _ := os.ReadFile(path)
	w.Write(data)
}

// BUG: no containment check after join
func readHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	path := filepath.Join(uploadDir, name)
	// filepath.Join cleans ".." but doesn't verify result is under uploadDir
	http.ServeFile(w, r, path)
}

func main() {
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/read", readHandler)
	http.ListenAndServe(":8080", nil)
}
