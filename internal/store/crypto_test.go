package store

import (
	"strings"
	"testing"
)

func TestCrypterRoundTrip(t *testing.T) {
	c, err := newCrypter([]byte("engagement-secret-passphrase"))
	if err != nil {
		t.Fatalf("newCrypter: %v", err)
	}
	for _, plain := range []string{
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.payload.sig",
		"a",
		strings.Repeat("x", 4096),
	} {
		ct := c.encrypt(plain)
		if !strings.HasPrefix(ct, encPrefix) {
			t.Fatalf("ciphertext missing prefix: %q", ct)
		}
		if ct == plain {
			t.Fatalf("ciphertext equals plaintext for %q", plain)
		}
		if got := c.decrypt(ct); got != plain {
			t.Fatalf("round-trip = %q, want %q", got, plain)
		}
	}
}

func TestCrypterEmptyAndAlreadyEncrypted(t *testing.T) {
	c, _ := newCrypter([]byte("k"))
	if got := c.encrypt(""); got != "" {
		t.Fatalf("encrypt(\"\") = %q, want empty", got)
	}
	ct := c.encrypt("secret")
	if again := c.encrypt(ct); again != ct {
		t.Fatalf("double-encrypt changed value: %q -> %q", ct, again)
	}
}

func TestCrypterNilReceiverPassthrough(t *testing.T) {
	var c *crypter // encryption disabled
	if got := c.encrypt("plain"); got != "plain" {
		t.Fatalf("nil encrypt = %q, want plain", got)
	}
	if got := c.decrypt("plain"); got != "plain" {
		t.Fatalf("nil decrypt = %q, want plain", got)
	}
}

func TestCrypterLegacyPlaintextPassthrough(t *testing.T) {
	c, _ := newCrypter([]byte("k"))
	// A value without the prefix predates encryption-at-rest and must survive.
	if got := c.decrypt("legacy-plaintext-token"); got != "legacy-plaintext-token" {
		t.Fatalf("legacy decrypt = %q, want verbatim", got)
	}
}

func TestCrypterWrongKeyReturnsVerbatim(t *testing.T) {
	a, _ := newCrypter([]byte("key-a"))
	b, _ := newCrypter([]byte("key-b"))
	ct := a.encrypt("secret")
	// Decrypting with the wrong key must fail closed to the stored value, never panic.
	if got := b.decrypt(ct); got != ct {
		t.Fatalf("wrong-key decrypt = %q, want stored ciphertext verbatim", got)
	}
}
