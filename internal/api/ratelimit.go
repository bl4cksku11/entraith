package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// loginLimiter throttles authentication attempts to defeat brute-force against
// the internet-exposed operator console. It tracks failures on two axes:
//
//   - per-username: the primary, non-spoofable control. After maxUserFails
//     failures inside the window the account is locked for lockoutDuration.
//   - per-IP: a coarse backstop against credential-stuffing across many
//     usernames from one source.
//
// State is in-memory only (resets on restart), which is appropriate for a
// single-node engagement console.
type loginLimiter struct {
	mu      sync.Mutex
	users   map[string]*failRecord
	ips     map[string]*failRecord
	lastGC  time.Time
}

type failRecord struct {
	count     int
	firstFail time.Time
	lockUntil time.Time
}

const (
	maxUserFails    = 5
	maxIPFails      = 20
	failWindow      = 15 * time.Minute
	lockoutDuration = 15 * time.Minute
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		users: make(map[string]*failRecord),
		ips:   make(map[string]*failRecord),
	}
}

// allowed reports whether a login attempt for (username, ip) may proceed. If
// locked, it returns the number of seconds the caller should wait.
func (l *loginLimiter) allowed(username, ip string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.gc(now)

	if r := l.users[strings.ToLower(username)]; r != nil && now.Before(r.lockUntil) {
		return false, int(time.Until(r.lockUntil).Seconds()) + 1
	}
	if r := l.ips[ip]; r != nil && now.Before(r.lockUntil) {
		return false, int(time.Until(r.lockUntil).Seconds()) + 1
	}
	return true, 0
}

// recordFailure registers a failed attempt and locks the account/IP once the
// threshold is crossed.
func (l *loginLimiter) recordFailure(username, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	bump(l.users, strings.ToLower(username), now, maxUserFails)
	bump(l.ips, ip, now, maxIPFails)
}

// recordSuccess clears the counters for a username/IP on a good login.
func (l *loginLimiter) recordSuccess(username, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.users, strings.ToLower(username))
	delete(l.ips, ip)
}

func bump(m map[string]*failRecord, key string, now time.Time, max int) {
	r := m[key]
	if r == nil || now.Sub(r.firstFail) > failWindow {
		r = &failRecord{firstFail: now}
		m[key] = r
	}
	r.count++
	if r.count >= max {
		r.lockUntil = now.Add(lockoutDuration)
	}
}

// gc drops stale records so the maps don't grow unbounded. Cheap and only runs
// at most once a minute.
func (l *loginLimiter) gc(now time.Time) {
	if now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now
	for k, r := range l.users {
		if now.After(r.lockUntil) && now.Sub(r.firstFail) > failWindow {
			delete(l.users, k)
		}
	}
	for k, r := range l.ips {
		if now.After(r.lockUntil) && now.Sub(r.firstFail) > failWindow {
			delete(l.ips, k)
		}
	}
}

// ClientIP is the exported form of clientIP for use by the main router's
// allowlist middleware.
func ClientIP(r *http.Request) string { return clientIP(r) }

// clientIP extracts the best-effort source IP. Behind the documented TLS
// reverse proxy (Caddy/nginx) the real client is in X-Forwarded-For /
// X-Real-IP; fall back to the transport peer otherwise. Spoofable headers only
// affect the coarse per-IP backstop — the per-username lock is authoritative.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
