// Package auth provides password hashing, token generation, and session
// utilities for the Entraith operator console.
//
// Passwords are hashed with argon2id (memory-hard, GPU/ASIC resistant) and
// stored in PHC string format. Legacy SHA-256+salt hashes from earlier
// versions are still verifiable so existing operator accounts keep working;
// callers should rehash transparently on the next successful login (see
// NeedsRehash).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

// argon2id parameters. Tuned for an interactive login on a typical VPS:
// ~64 MB memory, 3 passes. Encoded into every hash so they can be raised
// later without breaking existing hashes.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// GeneratePassword returns a random password of n characters from a strong
// charset, sampled without modulo bias.
func GeneratePassword(n int) string {
	result := make([]byte, n)
	// Rejection-sample to avoid the modulo bias of v%len(charset).
	max := byte(256 - (256 % len(passwordCharset)))
	i := 0
	buf := make([]byte, 1)
	for i < n {
		if _, err := rand.Read(buf); err != nil {
			continue
		}
		if buf[0] >= max {
			continue // would bias the distribution; resample
		}
		result[i] = passwordCharset[int(buf[0])%len(passwordCharset)]
		i++
	}
	return string(result)
}

// GenerateSalt returns a 16-byte random hex salt. Retained for legacy callers;
// argon2id hashes carry their own embedded salt.
func GenerateSalt() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// HashPassword returns an argon2id PHC string for the given password. A random
// salt is generated internally and embedded in the returned string, so no
// separate salt column is needed for new hashes.
func HashPassword(password string) string {
	salt := make([]byte, argonSaltLen)
	rand.Read(salt) //nolint:errcheck
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// VerifyPassword checks a password against a stored hash. It accepts both the
// new argon2id PHC format (salt embedded, the `salt` argument is ignored) and
// the legacy SHA-256+salt format. All comparisons are constant-time.
func VerifyPassword(password, stored, salt string) bool {
	if strings.HasPrefix(stored, "$argon2id$") {
		return verifyArgon2id(password, stored)
	}
	// Legacy SHA-256(password+salt)
	want, err := hex.DecodeString(stored)
	if err != nil {
		return false
	}
	h := sha256.Sum256([]byte(password + salt))
	return subtle.ConstantTimeCompare(h[:], want) == 1
}

// NeedsRehash reports whether a stored hash uses an outdated scheme and should
// be transparently upgraded after a successful login.
func NeedsRehash(stored string) bool {
	return !strings.HasPrefix(stored, "$argon2id$")
}

func verifyArgon2id(password, phc string) bool {
	// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GenerateToken returns a 32-byte cryptographically random hex token.
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
