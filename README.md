# Entraith

Entraith is a self-hosted console for running Microsoft device-code phishing during authorized red team work, with a post-exploitation suite for Entra ID and Microsoft 365 built on top of the tokens it captures.

It abuses the OAuth2 Device Authorization Grant (RFC 8628). The operator requests a device code per target, delivers the user code by email, and polls Microsoft for the token once the target authenticates. The target completes MFA themselves against the real Microsoft login page, so the resulting access and refresh tokens carry full trust without Entraith ever touching credentials or MFA.

> For authorized assessments only. You need written permission from the target organization before running this against their users or tenant. See [Legal](#legal).

## How it works

```
Entraith → POST /devicecode (client_id, scope)        → Microsoft
         ← {device_code, user_code "ABCD-EFGH", uri}

Entraith → phishing email to target: "go to microsoft.com/devicelogin, enter ABCD-EFGH"

Target authenticates with MFA on the real Microsoft page

Entraith → POST /token?device_code=... (polled)        → Microsoft
         ← {access_token, refresh_token, id_token}
Entraith → GET /me → resolves the UPN, stores the token, notifies the operator
```

Each target gets a unique code tied to their session, so captured tokens correlate back to the right person. The refresh token keeps working long after the device-code window closes. Full walkthrough in [docs/operator-guide.md](docs/operator-guide.md).

## What it does

- Device-code phishing campaigns with per-target codes, email delivery, and live capture over SSE.
- Three delivery modes: direct device code, QR landing page, and an Intune-style enrollment lookalike.
- Token handling: capture, refresh, cross-resource exchange (SharePoint, Azure, Key Vault, and others), and JSON export for evidence.
- Graph post-exploitation: mail, OneDrive/SharePoint, Teams, user and group enumeration, app registrations, conditional access, M365 search.
- Entra ID tradecraft: MFA method manipulation, virtual device registration, PRT request and conversion to access tokens or SSO cookies, Windows Hello key registration.
- Tenant persistence (CA exclusions, SP credential backdoors, role assignments) recorded in a deployment ledger with one-click teardown.
- Built-in mailer with sender profiles and templates, plus a webhook/beacon receiver.
- Multi-operator with admin/operator roles and session auth.
- Single Go binary with embedded UI, SQLite storage, no CGO.

## Quick start

### Docker

```bash
docker build -t entraith .
docker run -d --name entraith -p 8443:8443 -v entraith-data:/data entraith
docker logs entraith        # prints the first-run admin password
```

Open `http://localhost:8443/login`. The bundled `engagement.docker.conf` is a local demo config and sets `secure_cookies = false` for plain HTTP on localhost. Do not use it for a real engagement.

### From source

```bash
go build -o entraith ./cmd/entraith
./entraith server --config engagement.conf
```

```bash
./entraith validate    --config engagement.conf   # check the config without starting
./entraith reset-admin --config engagement.conf   # reset the admin password
./entraith version
```

On first run a random admin password is printed to stdout. Navigate to `/login`, authenticate, and you will be asked to change it.

## Configuration

A minimal config:

```ini
engagement.id  = CORP-2026-RTO-001
server.host    = 0.0.0.0
server.port    = 8443
campaign.tenant_id = common
campaign.client_id = d3590ed6-52b3-4102-aeff-aad2292ab01c
campaign.scope     = https://graph.microsoft.com/.default offline_access openid profile
storage.artifacts_path = /opt/entraith/data/artifacts
storage.exports_path   = /opt/entraith/data/exports
```

The SQLite database is created next to the artifacts path on first run. Full reference, including TLS, cookie, allowlist, and encryption options, is in [docs/configuration.md](docs/configuration.md).

## Deployment

The console is built to run behind a TLS-terminating reverse proxy (Caddy or nginx). Run one instance per engagement on a dedicated host, and bind to `0.0.0.0` only with the proxy in front.

- Use a purpose-registered sending domain with SPF, DKIM, and DMARC aligned to the from address.
- Register and age the phishing domain ahead of the engagement.
- Restrict the console to your own IPs with `server.ip_allowlist`; the target-facing endpoints stay open.
- Route operator traffic over a VPN or SSH tunnel.
- Export campaign data, then delete the campaign to wipe the database before tearing the box down.

Tradecraft details (User-Agent handling, polling jitter, request spacing, email header hygiene) are in [docs/security.md](docs/security.md).

## Security

The console handles live tokens for the client tenant and is reachable from the internet, so it is hardened accordingly: argon2id password hashing, login rate-limiting, AES-256-GCM encryption of all secrets at rest, authenticated webhook controls, a sanitized health endpoint, CSP and secure cookies, and an optional IP allowlist. The attack path and the target-facing pages are deliberately left untouched. See [docs/security.md](docs/security.md), and read the encryption-key note there before your first real run.

## Documentation

- [Operator guide](docs/operator-guide.md) — campaign workflow, QR and Intune phishing, mail, token management, Graph post-exploitation.
- [Advanced tools](docs/advanced-tools.md) — MFA manipulation, device registration, PRT operations, token exchange, persistence and teardown.
- [Configuration](docs/configuration.md) — config reference, roles and access control, database, webhook listener.
- [Architecture](docs/architecture.md) — components, data flow, package layout.
- [API reference](docs/api-reference.md) — every HTTP endpoint.
- [Security](docs/security.md) — console hardening, encryption key, tradecraft.

## Legal

For authorized security assessments only. You must have explicit written permission from the target organization before running this tool against their users or infrastructure. Unauthorized use is illegal.
