// Test case: file-upload (A04:2025)
package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// BUG: uploads stored in webroot
const uploadDir = "./public/uploads/"

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// BUG: no file size limit — MaxBytesReader not used
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}
	defer file.Close()

	// BUG: user-controlled filename used directly — path traversal via ../
	// BUG: no extension allowlist — attacker can upload .html, .php, .cgi
	dest := filepath.Join(uploadDir, header.Filename)
	out, err := os.Create(dest)
	if err != nil {
		http.Error(w, "Failed to save", 500)
		return
	}
	defer out.Close()
	io.Copy(out, file)
	w.Write([]byte("Uploaded: " + header.Filename))
}

func main() {
	http.HandleFunc("/upload", uploadHandler)
	http.ListenAndServe(":8080", nil)
}
