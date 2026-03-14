// Package auth provides password hashing, token generation, and session
// utilities for the Entraith operator console.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

// GeneratePassword returns a random password of n characters from a strong charset.
func GeneratePassword(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	result := make([]byte, n)
	for i, v := range b {
		result[i] = passwordCharset[int(v)%len(passwordCharset)]
	}
	return string(result)
}

// GenerateSalt returns a 16-byte random hex salt.
func GenerateSalt() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// HashPassword returns SHA-256(password+salt) as hex.
func HashPassword(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(password + salt))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyPassword checks if password matches the stored hash+salt.
func VerifyPassword(password, hash, salt string) bool {
	return HashPassword(password, salt) == hash
}

// GenerateToken returns a 32-byte cryptographically random hex token.
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
