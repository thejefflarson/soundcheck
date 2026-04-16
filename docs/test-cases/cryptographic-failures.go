// Test case: cryptographic-failures (A02:2025)
package vault

import (
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
)

// BUG: hardcoded encryption key in source control
var encryptionKey = []byte("hardcoded-key-16")

func HashPassword(password string) string {
	// BUG: MD5 is broken for password hashing — use bcrypt/argon2
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

func NewSessionToken() string {
	// BUG: math/rand is not cryptographically secure — use crypto/rand
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(b)
}

func EncryptLegacy(plaintext []byte) ([]byte, error) {
	// BUG: DES is obsolete (56-bit key, brute-forceable)
	block, err := des.NewCipher([]byte("8bytekey"))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	block.Encrypt(out, plaintext)
	return out, nil
}

func EncryptECB(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	// BUG: ECB mode leaks plaintext structure — use AES-GCM
	out := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		block.Encrypt(out[i:i+block.BlockSize()], plaintext[i:i+block.BlockSize()])
	}
	fmt.Println("encrypted")
	return out, nil
}
