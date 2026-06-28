package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// encPrefix marks a value as ENTRAITH-encrypted at rest. Values without it are
// treated as legacy plaintext and returned as-is on read, so an existing
// database keeps working and rows migrate to ciphertext the next time they are
// written.
const encPrefix = "enc:v1:"

// crypter performs authenticated encryption (AES-256-GCM) of secret column
// values. The data key is derived from the operator's configured secret with
// SHA-256, so any passphrase length is accepted.
type crypter struct {
	aead cipher.AEAD
}

func newCrypter(key []byte) (*crypter, error) {
	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:]) // 32-byte key → AES-256
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &crypter{aead: aead}, nil
}

// encrypt returns the ciphertext form of plain. Nil receiver (encryption
// disabled), empty input, or already-encrypted input pass through unchanged so
// the call is always safe at a write site.
func (c *crypter) encrypt(plain string) string {
	if c == nil || plain == "" || strings.HasPrefix(plain, encPrefix) {
		return plain
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return plain // never store a predictable nonce; fail open to plaintext
	}
	ct := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return encPrefix + base64.RawStdEncoding.EncodeToString(ct)
}

// decrypt reverses encrypt. Values lacking the prefix are legacy plaintext and
// returned unchanged. A decryption failure (wrong key, corruption) returns the
// stored value verbatim rather than panicking.
func (c *crypter) decrypt(s string) string {
	if c == nil || !strings.HasPrefix(s, encPrefix) {
		return s
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil {
		return s
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return s
	}
	pt, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return s
	}
	return string(pt)
}

// SetEncryptionKey enables encryption-at-rest for secret columns using the
// given key material. Call once at startup before loading state.
func (s *Store) SetEncryptionKey(key []byte) error {
	c, err := newCrypter(key)
	if err != nil {
		return err
	}
	s.enc = c
	return nil
}

// enc/dec are the nil-safe field helpers used by the CRUD layer.
func (s *Store) encF(v string) string { return s.enc.encrypt(v) }
func (s *Store) decF(v string) string { return s.enc.decrypt(v) }
