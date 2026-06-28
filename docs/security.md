# Security

The tool runs an operator console that sits on the internet during an engagement. Two separate things matter here: the tradecraft that keeps the attack quiet, and the hardening that keeps the console itself from becoming a liability if someone finds it. Both are covered below.

## Console hardening

The console holds live tokens for the client tenant, so treat the host it runs on as sensitive.

**Authentication.** Operator passwords are hashed with argon2id. SHA-256 hashes from earlier builds still verify and are re-hashed to argon2id on the next successful login, so existing accounts keep working with no migration step. Password comparison is constant-time.

**Login throttling.** Five failed logins for an account, or twenty from one IP, within 15 minutes locks further attempts for 15 minutes and returns 429. The counters live in memory and reset on restart. If you lock yourself out, `entraith reset-admin` from the CLI still works.

**Encryption at rest.** Captured access and refresh tokens, PRTs and their session keys, SMTP passwords, OTP secrets, device-certificate private keys and Windows Hello keys are encrypted with AES-256-GCM before they reach SQLite. If the database file leaks, none of those come out readable. Decryption happens when the app reads a row, so nothing in the attack path changes.

**Exposure.** `/health` returns only `{"status":"ok"}` with no engagement or operator identifiers. Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` by default. Console pages set a CSP plus the usual anti-clickjacking and nosniff headers. The target-facing landing pages (`/qr`, `/intune`) get none of that, on purpose, so they stay unremarkable to a scanner.

**Webhook controls.** `/receive` is the always-on beacon receiver and stays public. The control endpoints (`/webhook/start`, `/webhook/stop`, `/webhook/status`, `/webhook/logs`) require an operator session.

**Network restriction.** `server.ip_allowlist` limits the console to known source IPs while leaving the phishing and beacon endpoints open. A non-allowed source gets a 404 instead of a login page.

## Encryption key

The at-rest key comes from one of two places:

1. `auth.secret_key` in the config, if you set it. Any length; it is run through SHA-256 to derive the AES key.
2. Otherwise a random 32-byte key written to `<parent of artifacts_path>/.entraith.key` (mode 0600) on first run.

Pick one source and keep it for the life of the database. Switch sources, or lose the key file, and the rows encrypted under the old key can no longer be decrypted, which means the tokens are gone. Back the key file up with the rest of the engagement data. A database written before encryption was added still works: legacy plaintext rows are read as-is and re-encrypted the next time they change.

## Secure cookies and local HTTP

`server.secure_cookies` defaults to on. Behind a TLS proxy or with `server.tls`, leave it on. Browsers also send Secure cookies to `http://localhost`, so local testing is fine. Set it to `false` only when you reach the console over plain HTTP on a non-localhost address, or the browser will drop the session cookie and login will look like it silently fails.

## Build note

`golang.org/x/crypto` is pinned to v0.36.0 so the module stays on the `go 1.24` toolchain; newer releases require go 1.25. Build with `GOTOOLCHAIN=local` if your installed Go is older than the toolchain directive.

---

## Tradecraft

### User-Agent spoofing

All outbound HTTP requests to Microsoft endpoints use a realistic Windows browser User-Agent. One UA is chosen at `Engine` creation and used consistently for all requests in that campaign.

### Polling jitter

Each polling goroutine sleeps `interval ± 30%` between polls, computed independently. `slow_down` responses trigger additional jittered backoff (base 10s ± 30%).

### Device code request spacing

Campaign launch issues device code requests sequentially with a random **800ms–3000ms** delay between each — avoiding burst patterns in Microsoft's auth logs.

### Email header hygiene

- `Message-ID` — 16 bytes `crypto/rand`, scoped to sender domain, unique per message
- `Date` — RFC 5322 from actual send time
- MIME boundary — 12 bytes `crypto/rand` per message
- No `X-Mailer` or `X-Originating-IP`

### Source code hygiene

All HTML files served to targets (`qrlanding.html`) and publicly reachable pages (`login.html`) are stripped of operator comments, tool-identifying strings in HTML comments, and phishing-indicative JS annotations. Pages behind authentication (`dashboard.html`, `infra.html`, `tools.html`) are also comment-clean. If you modify any HTML, avoid re-introducing comments that reveal tool purpose or operator intent.

### Deployment checklist

| Control | Recommendation |
|---------|----------------|
| **Infrastructure** | Dedicated VPS per engagement, not shared or reused |
| **SMTP account** | Purpose-registered domain with SPF, DKIM, DMARC aligned to `from_address` |
| **Domain age** | Register phishing domain weeks before the engagement |
| **TLS** | Run behind Caddy or nginx with a real certificate |
| **Egress** | Route operator traffic through a VPN or SSH tunnel |
| **Access** | Bind to `0.0.0.0` to expose publicly; put TLS termination (Caddy/nginx) in front if not using a direct cert |
| **Cleanup** | Export campaign data, then Delete to wipe the database before leaving infrastructure |

---

