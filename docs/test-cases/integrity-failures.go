// Test case: integrity-failures (A08:2025)
package main

import (
	"encoding/gob"
	"io"
	"net/http"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)

type Session struct {
	UserID string
	Admin  bool
}

func LoadSession(r io.Reader) (*Session, error) {
	var s Session
	dec := gob.NewDecoder(r)
	// BUG: gob.Decode on an untrusted reader can panic the process and
	// reconstructs attacker-controlled fields without schema validation.
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func LoadConfig(raw []byte) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	// BUG: yaml.Unmarshal into a free-form map skips schema validation,
	// trusting whatever types and keys the attacker supplies.
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func InstallUpdate(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, _ := os.Create("/tmp/update.bin")
	io.Copy(f, resp.Body)
	f.Close()
	// BUG: no sha256/signature verification before executing the binary
	return exec.Command("/tmp/update.bin").Run()
}
