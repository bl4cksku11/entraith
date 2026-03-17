# ENTRAITH

Device Code Phishing Operator Console — a self-hosted platform for conducting Microsoft OAuth2 Device Authorization Grant attacks during authorized red team assessments. Includes a full post-exploitation suite covering Microsoft Graph API operations, MFA manipulation, device registration, Primary Refresh Token (PRT) operations, and token exchange — all accessible from a multi-page operator dashboard protected by session-based authentication.

---

## Table of Contents

1. [How the attack works](#how-the-attack-works)
2. [Architecture](#architecture)
3. [Code structure](#code-structure)
4. [Setup and configuration](#setup-and-configuration)
5. [Operator workflow](#operator-workflow)
6. [QR phishing](#qr-phishing)
7. [Mail system](#mail-system)
8. [Advanced Tools](#advanced-tools)
9. [OPSEC](#opsec)
10. [Persistence and database](#persistence-and-database)
11. [API reference](#api-reference)
12. [Artifacts and evidence](#artifacts-and-evidence)
13. [Post-exploitation (Graph Ops)](#post-exploitation-graph-ops)
14. [Webhook listener](#webhook-listener)

---

## How the attack works

The Microsoft Device Authorization Grant (RFC 8628) is an OAuth2 flow designed for input-constrained devices (TVs, printers, CLI tools) that cannot open a browser. ENTRAITH abuses this flow against human targets.

### Normal legitimate flow

```
Device (CLI/TV)  →  POST /devicecode  →  Microsoft
                 ←  {device_code, user_code, verification_uri}

Device shows:  "Visit microsoft.com/devicelogin and enter: ABCD-EFGH"

User opens browser, visits verification_uri, enters user_code, authenticates with MFA

Device polls:  POST /token?device_code=...
Microsoft:  ←  {access_token, refresh_token, id_token}
```

### What ENTRAITH does instead

The operator becomes the "device." Microsoft issues a `device_code` per request with no requirement that a real device initiated it — only a valid `client_id` and `scope` are needed. ENTRAITH requests one `device_code` per target, extracts the `user_code`, and delivers it to that specific target via a phishing email. Each target gets a unique code tied to their session. When a target authenticates, the token is captured and correlated back to them.

```
ENTRAITH  →  POST /devicecode (client_id, scope)  →  Microsoft
          ←  {device_code, user_code="ABCD-EFGH", verification_uri}

ENTRAITH  →  Phishing email to target@corp.com:
               "Visit microsoft.com/devicelogin and enter: ABCD-EFGH"

Target opens email, visits URL, enters their unique code, completes MFA

ENTRAITH polls:  POST /token?device_code=...  (every N seconds with jitter)
Microsoft:    ←  {access_token, refresh_token, id_token}

ENTRAITH  →  GET /me  →  Microsoft Graph
          ←  {userPrincipalName: "target@corp.com"}

Token saved to SQLite, UPN correlated, operator notified in real time.
```

### Why it bypasses MFA

The target completes MFA themselves — against the legitimate Microsoft login page. ENTRAITH never touches the credentials or MFA. The resulting tokens carry the same trust level as if a real device had initiated the flow. The access token grants API access; the refresh token can be exchanged for new access tokens long after the session ends.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  cmd/entraith/main.go                                                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐│
│  │ campaigns.      │  │  mailer.Manager  │  │  api.Handler            ││
│  │ Manager         │  │  (profiles,      │  │  (HTTP routes,          ││
│  │ (campaigns,     │  │   templates)     │  │   wires managers,       ││
│  │  polling)       │  │                  │  │   session auth)         ││
│  └──────┬──────────┘  └────────┬─────────┘  └─────────────────────────┘│
│         └──────────────────────┘                                        │
│                    ▼                                                     │
│           ┌─────────────────┐                                           │
│           │  store.Store    │  ← SQLite (entraith.db)                   │
│           │  campaigns      │    WAL mode, FK cascade                   │
│           │  targets        │                                           │
│           │  device_codes   │                                           │
│           │  tokens         │                                           │
│           │  email_results  │                                           │
│           │  profiles       │                                           │
│           │  templates      │                                           │
│           │  sessions       │  ← operator login sessions                │
│           │  device_certs   │  ← registered virtual devices             │
│           │  prts           │  ← Primary Refresh Tokens                 │
│           │  winhello_keys  │  ← Windows Hello keys                     │
│           │  otp_secrets    │  ← stored TOTP secrets                    │
│           └─────────────────┘                                           │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  devicecode.Engine  (per campaign, in-memory only)              │   │
│  │  - one goroutine per target for polling                         │   │
│  │  - jittered sleep intervals                                     │   │
│  │  - spoofed User-Agent                                           │   │
│  │  - Results chan → collectResults goroutine                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  graph.Client  (stateless, per Graph Ops request)               │   │
│  │  - email browse/send/reply/forward, folder navigation           │   │
│  │  - OneDrive/SharePoint browse, download, upload, delete         │   │
│  │  - Teams chats, channels, messages, send                        │   │
│  │  - user/group enumeration with deep group inspection            │   │
│  │  - app registrations, service principals, OAuth2 grants         │   │
│  │  - conditional access policies, auth methods                    │   │
│  │  - M365 cross-resource search                                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Advanced modules (Advanced Tools page)                         │   │
│  │  mfa         — list/add/delete MFA methods, register TOTP/FIDO2│   │
│  │  devicereg   — virtual device registration (AAD Join / WPJOIN)  │   │
│  │  prt         — Primary Refresh Token request and conversion     │   │
│  │  tokenexchange — v1/v2 token exchange, cross-resource tokens    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
           │                          │
           ▼                          ▼
  login.microsoftonline.com    graph.microsoft.com
  (device codes + polling,     (/me, Graph Ops post-exploitation)
   token refresh, PRT ops)
```

### Data flow on launch

```
Manager.Launch(campaignID)
  │
  ├─ for each target (sequential, jittered delay 800ms–3s):
  │    Engine.RequestDeviceCode(targetID, email)
  │      └─ POST /devicecode → Microsoft
  │         store session{device_code, user_code, state=pending}
  │         db.UpsertDeviceCode() → SQLite device_codes table
  │
  ├─ for each code:
  │    Engine.StartPolling(ctx, targetID)
  │      └─ goroutine: loop {
  │             sleep(interval ± 30% jitter)
  │             POST /token?device_code=...
  │             if completed → resolveUPN() → Results <- token
  │             if expired/error → mark session, return
  │           }
  │
  └─ go collectResults(ctx, campaign)
       └─ for result := range Engine.Results:
            c.Results = append(...)
            db.InsertToken() → SQLite tokens table
            db.UpsertCampaign() → update status/counts
            log "[+] TOKEN CAPTURED"
```

### Campaign state machine

```
Draft ──[Launch]──► Running ──[Stop]──► Aborted
                      │
                      └──[all tokens received or codes expired]──► Completed

[restart] Running → Aborted  (polling goroutines cannot survive restart)
```

### Session state machine (per target)

```
                                [QR email sent]
                                      │
                                  qr_sent  (placeholder — no device code yet)
                                      │
                              [target scans QR]
                                      │
Initializing ──[RequestDeviceCode]──► Pending
                                        │
                   ┌────────────────────┤
                   ▼                    ▼
               Completed            Expired
               (token captured)     (15 min elapsed)
                                        │
                                    Error / Cancelled
```

If a target scans the QR code a second time, the previous polling goroutine is cancelled and a new device code is issued from scratch.

---

## Code structure

```
entraith/
├── cmd/
│   └── entraith/
│       └── main.go              # CLI entry: server / validate / version
│                                # Session-guarded page routing (pageGuard)
│                                # Opens SQLite, wires managers
│
├── internal/
│   ├── auth/
│   │   └── auth.go              # Password hashing (SHA-256 + salt), token generation
│   │
│   ├── config/
│   │   └── config.go            # key=value config parser, defaults
│   │
│   ├── store/
│   │   └── store.go             # SQLite persistence layer
│   │                            # Schema migration (idempotent CREATE IF NOT EXISTS)
│   │                            # CRUD for all entities including sessions,
│   │                            # device certs, PRTs, WinHello keys, OTP secrets
│   │
│   ├── campaigns/
│   │   └── campaigns.go         # Campaign lifecycle, Manager, Launch, SendEmails
│   │                            # SendQREmails (bulk + per-target), RefreshToken
│   │                            # Load(), DeleteCampaign(), ExportCampaign()
│   │
│   ├── modules/
│   │   ├── devicecode/
│   │   │   └── devicecode.go    # Engine, session state, polling goroutines
│   │   │                        # RefreshAccessToken() — exchange refresh_token
│   │   ├── graph/
│   │   │   └── graph.go         # Microsoft Graph API post-exploitation client
│   │   │                        # Email, OneDrive/SharePoint, Teams, users, groups
│   │   │                        # Apps, policies, M365 search, auth methods
│   │   ├── mfa/
│   │   │   └── mfa.go           # My Sign-ins API client
│   │   │                        # List/add/delete/verify MFA methods
│   │   │                        # TOTP registration with server-side code gen
│   │   │                        # FIDO2 key registration flow
│   │   ├── devicereg/
│   │   │   └── device.go        # Entra ID device registration
│   │   │                        # AAD Join / Workplace Join (WPJOIN)
│   │   │                        # Generates RSA keypair + self-signed cert
│   │   ├── prt/
│   │   │   └── prt.go           # Primary Refresh Token operations
│   │   │                        # Request PRT from refresh token + device cert
│   │   │                        # Convert PRT → access token or SSO cookie
│   │   │                        # Windows Hello for Business NGC key registration
│   │   └── tokenexchange/
│   │       └── exchange.go      # OAuth2 token exchange (v1.0 + v2.0)
│   │                            # Cross-resource token minting, tenant lookup
│   │
│   ├── targets/
│   │   └── targets.go           # In-memory target store, CSV import
│   │
│   ├── mailer/
│   │   └── mailer.go            # SenderProfile, EmailTemplate, Render, Send, MIME
│   │                            # Callback-based persistence (injected from main.go)
│   │
│   ├── api/
│   │   ├── handler.go           # All HTTP handlers and route registration
│   │   │                        # Auth, campaigns, targets, Graph Ops, MFA,
│   │   │                        # device certs, PRTs, WinHello, OTP, token exchange
│   │   └── webhook.go           # Standalone webhook listener goroutine
│   │                            # Start/stop/log the secondary HTTP listener
│   │
│   └── web/
│       ├── pages.go             # go:embed declarations for all HTML files
│       ├── login.html           # Login page (public, session cookie auth)
│       ├── dashboard.html       # Operations console (SPA — campaigns, mail,
│       │                        # Graph Ops, QR phishing, webhook listener)
│       ├── tools.html           # Advanced Tools (MFA, device reg, PRT, token exchange)
│       ├── infra.html           # Infrastructure page (sender profiles, templates)
│       └── qrlanding.html       # QR scan landing page — editable; served to targets
│                                # on GET /qr/{token}; fires confirm POST on load
│
└── bootstrap/
    ├── engagement.example.conf  # Example key=value config
    └── targets.example.csv      # Example target list
```

### Package responsibilities

**`auth`** — password hashing (`SHA-256` + random hex salt), password verification, random password generation, and cryptographically random session token generation. Used by `main.go` to create the first-run admin user and by `api` for login/logout.

**`config`** — loads a flat `key=value` config file (comments with `#`, inline comments stripped). Sets safe defaults for missing values. No external dependencies.

**`store`** — the SQLite persistence layer (`modernc.org/sqlite`, pure Go, no CGO). Opened once at startup and shared by both managers. Schema applied via `CREATE TABLE IF NOT EXISTS` on every startup (idempotent). Foreign keys with `ON DELETE CASCADE` cascade deletes from campaigns to all associated rows. Stores sessions (operator login), device certificates, PRTs, Windows Hello keys, and OTP secrets in addition to campaign data.

**`campaigns`** — owns the `Manager` (map of campaigns, mutex-protected). Each `Campaign` holds a `*targets.Store`, a `*devicecode.Engine`, result slices, email send results, and a buffered `notify` channel for instant SSE pushes. `Manager.Load()` reads all campaigns from SQLite at startup. `Manager.Launch` orchestrates the device code flow. `Manager.SendQREmails` handles bulk or per-target QR phishing email dispatch. `Manager.NotifySSE` wakes any open SSE connections for a campaign immediately.

**`devicecode`** — the core engine. One `Engine` per campaign (in-memory only). Holds a `map[targetID]*Session`. Each `Session` carries a `cancel context.CancelFunc` — if a target scans a QR code a second time, the old polling goroutine is cancelled before a new session is stored, preventing stale polling of the invalidated code. `StartPolling` spawns one goroutine per target with a per-session child context. Results delivered via buffered channel. All requests use a consistent, spoofed User-Agent. The standalone `RefreshAccessToken` exchanges a `refresh_token` for a new pair.

**`graph`** — stateless Graph API client. `graph.New(accessToken)` wraps a Bearer token and exposes methods for every supported post-exploitation operation. All methods accept a `context.Context`. Covers full mail operations (browse folders, read/send/reply/forward/delete/attach), OneDrive (list, download, upload, delete, recent, shared), Teams (teams, channels, chats, messages, create chat, send), groups (info, members, transitive members, owners, drives, sites, app roles), users (info, member-of, batch), apps, grants, conditional access, auth methods, and M365 cross-resource search.

**`mfa`** — client for the My Sign-ins API (`mysignins.microsoft.com`). Requires an access token scoped to resource `19db86c3-b2b9-44cc-b339-36da233a3be2` (obtained automatically by exchanging the captured refresh token). Supports listing, adding, and deleting MFA methods; TOTP registration (with server-side `GenerateTOTP` for live code display); and FIDO2 key registration flow.

**`devicereg`** — registers a virtual device with Entra ID. Generates an RSA-2048 keypair and self-signed certificate, then submits a device registration request to `enterpriseregistration.windows.net`. Supports both AAD Join (`JoinTypeAADJoined`) and Workplace Join (`JoinTypeRegistered`). The resulting `DeviceCert` is required for PRT operations.

**`prt`** — Primary Refresh Token operations. `Request(ctx, refreshToken, clientID, dc)` uses the device cert to request a PRT from the v1.0 token endpoint via a signed JWT. `ToAccessToken` converts a PRT to an access token for any resource using HMAC-SHA256 signed JWTs and an encrypted request. `ToCookie` converts a PRT to a browser SSO cookie. `RegisterWinHello` registers a Windows Hello for Business NGC key bound to the device.

**`tokenexchange`** — exchanges a refresh token for an access token targeting a different resource or scope. Supports both v1.0 (`resource` parameter) and v2.0 (`scope` parameter) endpoints. `LookupTenantID` resolves a domain to its Entra tenant ID via the OIDC metadata endpoint.

**`targets`** — thread-safe in-memory store. Deduplicates by lowercase email. CSV import with flexible column detection (only `email` required). IDs are 8-byte random hex strings.

**`mailer`** — stateless send logic plus an in-memory manager for profiles and templates. Persistence injected by `main.go` via `SetPersistence(...)` callbacks. `Render` performs simple string replacement. `buildMIME` constructs RFC 5322 messages with per-message random `Message-ID` and MIME boundary from `crypto/rand`.

**`api`** — `Handler` holds pointers to all managers. `Routes()` returns a configured `*http.ServeMux` with all endpoints. Handles auth (login/logout/check), all campaign operations, Graph Ops, MFA, device certs, PRTs, Windows Hello, OTP secrets, token exchange, webhook management, and the public QR scan endpoints (`GET /qr/{token}`, `POST /qr/{token}/confirm`). The SSE handler (`streamEvents`) pushes an initial snapshot on connect and reacts to both the 2-second ticker and the campaign's `notify` channel.

**`web`** — five embedded HTML files (`go:embed`). No external JS dependencies. All pages communicate exclusively via the REST API and SSE for live updates. `qrlanding.html` is public-facing and served to targets who scan a QR code — it fires a background confirm POST then redirects. Operator sessions are enforced server-side by `pageGuard` in `main.go` — unauthenticated requests are redirected to `/login?next=<path>`.

---

## Setup and configuration

### Requirements

- Go 1.22+
- Outbound HTTPS to `login.microsoftonline.com`, `graph.microsoft.com`, `mysignins.microsoft.com`, `enterpriseregistration.windows.net`
- An SMTP account for sending phishing emails

### Build

```bash
go build -o entraith ./cmd/entraith
```

The binary embeds all HTML at compile time via `go:embed`. Runtime dependencies are only the config file and the SQLite database (created automatically on first run).

### Config file

```ini
# Engagement metadata
engagement.id         = CORP-2026-RTO-001
engagement.operator   = operator
engagement.client_code = CORPX

# Server
server.host = 0.0.0.0
server.port = 8443

# Azure AD / Entra ID
campaign.tenant_id    = common
campaign.client_id    = d3590ed6-52b3-4102-aeff-aad2292ab01c
campaign.scope        = https://graph.microsoft.com/.default offline_access openid profile
campaign.poll_interval = 5

# Storage (created automatically if missing)
storage.artifacts_path = /opt/entraith/data/artifacts
storage.exports_path   = /opt/entraith/data/exports
```

The SQLite database is created at `<parent of artifacts_path>/entraith.db`.

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
```

```bash
./entraith validate --config engagement.conf   # check config without starting
./entraith version
```

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

## Operator workflow

### Step 1 — Create a campaign

In the sidebar, enter a campaign name and optional description, then click **Create Campaign**. This creates a `Campaign` row in the database with status `draft`.

### Step 2 — Import targets

**Via CSV upload** — Required column: `email`. Optional: `display_name`, `department`, `region`, `group`, `custom_field`. Duplicates are silently skipped.

```csv
email,display_name,department,region,group
jsmith@corp.com,John Smith,Finance,US-East,executives
mary.jones@corp.com,Mary Jones,Finance,US-East,finance
```

**Via paste** — one email per line. Converted to minimal CSV before import.

### Step 3 — Configure mail

Go to **Infrastructure** (top nav) to create sender profiles and email templates. Profiles and templates are global — they persist across campaigns and server restarts.

### Step 4 — Launch the campaign

Click **▶ Launch Campaign**. For each target:
1. `Engine.RequestDeviceCode()` issues a `POST` to the Microsoft device code endpoint.
2. A random 800ms–3s delay is inserted between requests.
3. Each device code is written to the database and to `artifacts/{campaign_id}/device_codes.json`.
4. `Engine.StartPolling()` spawns a goroutine per target polling at the configured interval (±30% jitter).
5. A `collectResults` goroutine writes each captured token to the database immediately.

### Step 5 — Send phishing emails

Select a **Sender Profile** and **Email Template**, then click **✉ Send Phishing Emails** to deliver personalized device code emails to all targets. Use the per-row **→** button in the Sessions table to send to a single target.

Email sending is intentionally decoupled from launch — launch first to start the polling clock, then send.

### Step 6 — QR phishing (optional, replaces steps 4–5)

Switch the **Phishing Mode** dropdown in the sidebar to **QR** — this hides the normal launch/regen buttons and shows the QR Phishing section. Sending QR emails is all that's required — the campaign launches automatically when each target scans their code, and the DC email is sent to them at that moment. Targets appear in the Sessions tab immediately after the QR email is sent, with state `qr_sent`, and transition to `pending` once they scan. See [QR phishing](#qr-phishing) for the full flow.

### Step 7 — Monitor

Multiple campaigns can be open simultaneously as **tabs** at the top of the campaign view. Each tab maintains its own SSE connection and independent pagination state. Switching tabs saves and restores per-campaign state; closing a tab tears down the SSE connection.

The **Sessions** tab updates in real time via SSE (`/api/campaigns/{id}/events`). On connect, the first snapshot is pushed immediately. Subsequent updates are pushed every 2 seconds **and** instantly whenever a significant event occurs (DC email sent, token captured, campaign launched). The sidebar campaign status badge also updates live via SSE. When a token is captured, it appears in **Captured Tokens** with a flash notification.

### Step 8 — Token management

The **Captured Tokens** tab shows each token with:

- **↓ AT** — downloads the raw access token as `at_<upn>.txt`
- **↓ RT** — downloads the raw refresh token as `rt_<upn>.txt`
- **↺ Refresh** — exchanges the stored refresh token for new tokens; updates the database

### Step 9 — Post-exploitation (Graph Ops)

Click the **Graph Ops** tab. Select a captured target from the dropdown. See [Post-exploitation](#post-exploitation-graph-ops) for all available operations.

### Step 10 — Advanced operations

Navigate to **Advanced Tools** for MFA manipulation, device registration, PRT operations, and token exchange. See [Advanced Tools](#advanced-tools).

### Step 11 — Export evidence

Click **↓ Export Campaign** to download `campaign_<id>_export.json`, a complete evidence package with campaign metadata, all targets, device codes, tokens, and email results.

### Step 12 — Delete when done

Click **🗑 Delete Campaign**. After confirmation, the campaign and all associated data are permanently deleted via `ON DELETE CASCADE`. Export before deleting.

---

## QR phishing

QR phishing is an alternative delivery method that combines a device code flow with a scannable QR code — useful when targets are expected to complete authentication on a mobile device or when email link scanners would flag a direct Microsoft URL.

### How it works

The QR flow is **two-phase**. When the target scans the QR code the device code is not yet requested — it is requested on-demand at scan time:

1. The operator sends a **QR email** (contains the QR code image) via the **QR Phishing** section. No campaign launch or pre-issued device codes are needed. Each target immediately appears in the Sessions tab with state `qr_sent`.
2. The QR code encodes a unique URL on the operator's infrastructure: `<base_url>/qr/<token>`.
3. When the target scans the code, `GET /qr/<token>` serves a **landing page** (`qrlanding.html`) that fires a background `POST /qr/<token>/confirm` while immediately redirecting the target to `microsoft.com/devicelogin`.
4. On receiving the confirm POST, ENTRAITH:
   - Launches the campaign (if not already running).
   - Requests a fresh device code for that specific target. If the target scans a second time, the previous polling goroutine is cancelled before a new device code is issued.
   - Sends them the **DC email** (contains the user code) automatically.
   - Starts polling for the token. The session transitions from `qr_sent` to `pending`.
5. The target lands on the real Microsoft login page, receives the DC email seconds later, enters the user code, and authenticates. The token is captured automatically.

### Customizing the landing page

The landing page is embedded from `internal/web/qrlanding.html`. Edit it freely — logo, text, colors — then rebuild:

```bash
go build -o entraith ./cmd/entraith
```

The `fetch('/qr/{{TOKEN}}/confirm', ...)` call in the `<script>` block **must not be removed** — it is what registers the scan and triggers the device code email. `{{TOKEN}}` is replaced by the server at request time.

The redirect target at the bottom of the script (`window.location.replace(...)`) should point to wherever the target should land — default is `https://microsoft.com/devicelogin`.

### Template placeholders

| Placeholder | Resolved to |
|-------------|-------------|
| `{{QRC}}` | Base64-encoded PNG of the QR code for this target's unique redirect URL |

Use it in an `<img>` tag:

```html
<img src="data:image/png;base64,{{QRC}}" alt="QR Code" width="200" height="200">
```

The **DC email template** uses the standard `{{DCODE}}`, `{{URL}}`, `{{EMAIL}}`, `{{NAME}}` placeholders — it is the fallback code email that is sent automatically when the target scans the QR code.

### Sending

In the **QR Phishing** section of the Operations sidebar (visible when **Phishing Mode** is set to **QR**):

1. Select a **Sender Profile**, **QR email template**, and **DC email template**.
2. Enter the **Public Base URL** (e.g. `https://r.yourdomain.com`) — the server where ENTRAITH's `/qr/<token>` endpoint is reachable.
3. Click **⬛ Send QR Emails** to deliver the QR email to all targets. The DC email is sent **automatically at scan time** — no manual step needed.

> **Note:** Do not launch the campaign before sending QR emails. The launch happens automatically on the first scan of each target's code.

### QR scan tracking

After sending QR emails, targets appear in the **Sessions** tab with state `qr_sent` — confirming delivery before any scan has occurred. Once a target scans their code, the session transitions to `pending` and polling begins.

The **QR Scans** tab logs every confirmed scan event: timestamp, source IP, and which target's code was triggered. Each entry corresponds to a successful `POST /qr/{token}/confirm`. Query `GET /api/campaigns/{id}/qr-scans` for the full log.

---

## Mail system

### Sender profiles

| Field | Notes |
|-------|-------|
| `name` | Internal label |
| `host` | SMTP hostname |
| `port` | `587` (STARTTLS) or `465` (implicit TLS) |
| `username` | SMTP auth username |
| `password` | SMTP auth password — stored in SQLite at rest |
| `from_name` | Display name in the `From:` header |
| `from_address` | Sender email address |
| `implicit_tls` | `true` → TLS-on-connect (port 465); `false` → STARTTLS |

```
Office365:  host: smtp.office365.com  port: 587  implicit_tls: false
Gmail:      host: smtp.gmail.com      port: 587 or 465
```

Use **Test Send** to verify SMTP connectivity before a live campaign.

### Template placeholders

| Placeholder | Resolved to |
|-------------|-------------|
| `{{DCODE}}` | Target's unique user code — e.g. `ABCD-EFGH` |
| `{{URL}}` | Redirector URL if configured, otherwise the real Microsoft verification URI |
| `{{REALURL}}` | Always `https://microsoft.com/devicelogin` |
| `{{EMAIL}}` | Target's email address |
| `{{NAME}}` | Target's display name from the CSV |
| `{{QRC}}` | Base64 PNG of the QR code (QR phishing templates only) |

### Redirector URL

Set a **Redirector URL** on the template so links point to your infrastructure instead of `microsoft.com` directly. `{{URL}}` resolves to the redirector; `{{REALURL}}` always resolves to the real Microsoft URL.

### MIME construction

Each email is a proper RFC 5322 `multipart/alternative` message:

- `Message-ID` — 16 bytes from `crypto/rand`, scoped to the sender's domain
- `Date` — actual send time, RFC 5322 format
- MIME boundary — 12 bytes from `crypto/rand` per message
- No `X-Mailer`, `X-Originating-IP`, or other tool-identifying headers

---

## Advanced Tools

The **Advanced Tools** page (`/tools`) provides capabilities for post-capture operations that go beyond Graph API access. All modules are accessible from the top navigation.

### MFA manipulation

Requires an access token scoped to the My Sign-ins API resource. ENTRAITH automatically exchanges the target's captured refresh token when you select a target in any MFA operation.

| Operation | What it does |
|-----------|-------------|
| **List Methods** | Enumerates all registered MFA methods (phone, email, authenticator app, FIDO2, etc.) |
| **Add Phone** | Registers a mobile or office phone number as an MFA method |
| **Add Email** | Registers an email address as an MFA method |
| **Add Authenticator App (TOTP)** | Registers the operator's authenticator as a new TOTP app; displays the live OTP code |
| **Add Authenticator App (push)** | Registers push-only or push+OTP authenticator |
| **Verify Method** | Completes verification of a newly added method |
| **Delete Method** | Removes a registered MFA method |
| **FIDO2 Registration** | Initiates and completes FIDO2 security key registration |

TOTP secrets are stored in the database (`otp_secrets` table) and accessible via `GET /api/otp-secrets/{id}/code` for live code generation.

### Device registration

Registers a virtual device with Entra ID using the captured user's access token. The resulting device certificate is required for PRT operations.

| Field | Notes |
|-------|-------|
| **Label** | Friendly name for the cert (internal reference) |
| **Device type** | `Windows`, `iOS`, `Android`, `MacOS` |
| **Join type** | `AAD Join` (domain-joined) or `Workplace Join` (BYOD/registered) |
| **Target domain** | e.g. `corp.com` — used in the device certificate CN |
| **OS version** | e.g. `10.0.19045.0` |

ENTRAITH generates an RSA-2048 keypair and self-signed certificate locally, then submits the registration to `enterpriseregistration.windows.net`. The certificate and private key are stored in the database and used for subsequent PRT requests.

### Primary Refresh Token (PRT)

PRTs are device-bound tokens that survive password resets when bound to a device certificate. They can mint access tokens for any resource and generate browser SSO cookies.

| Operation | What it does |
|-----------|-------------|
| **Request PRT** | Exchanges a captured refresh token + device cert for a PRT via the v1.0 token endpoint |
| **Import PRT** | Paste a raw PRT obtained externally (e.g., from `ROADtools` or a compromised host) |
| **PRT → Access Token** | Converts the PRT to an access token for a specified resource using HMAC-SHA256 signed JWTs |
| **PRT → SSO Cookie** | Converts the PRT to a `x-ms-RefreshTokenCredential` browser cookie for SSO sessions |
| **Register WinHello Key** | Registers a Windows Hello for Business NGC key bound to the device cert |

### Token exchange

Exchanges a captured refresh token for an access token targeting a different resource — useful for pivoting from a Graph token to other Microsoft services.

| Field | Notes |
|-------|-------|
| **Protocol** | `v1.0` (uses `resource` parameter) or `v2.0` (uses `scope` parameter) |
| **Resource / Scope** | Target resource URI or scope string |
| **Client ID** | Optionally override the client ID used in the exchange |
| **Tenant lookup** | Resolve a domain to its Entra tenant ID |

Common resources for v1.0 exchange:

| Service | Resource URI |
|---------|-------------|
| Microsoft Graph | `https://graph.microsoft.com` |
| SharePoint | `https://<tenant>.sharepoint.com` |
| Azure Management | `https://management.azure.com` |
| Key Vault | `https://vault.azure.net` |
| My Sign-ins (MFA) | `19db86c3-b2b9-44cc-b339-36da233a3be2` |

---

## OPSEC

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

## Persistence and database

All operator data is stored in a single SQLite database (`entraith.db`). WAL mode, foreign keys enforced.

### Schema

```
campaigns        — campaign metadata (id, name, status, timestamps)
targets          — import list per campaign (CASCADE)
device_codes     — issued device codes per campaign (CASCADE)
tokens           — captured OAuth tokens per campaign (CASCADE)
email_results    — per-target email send outcomes (CASCADE)
sender_profiles  — SMTP accounts (global)
email_templates  — phishing HTML templates (global)
sessions         — operator login sessions (expiry-based)
device_certs     — registered virtual devices (global)
prts             — Primary Refresh Tokens (global)
winhello_keys    — Windows Hello for Business NGC keys (global)
otp_secrets      — stored TOTP secrets for live code generation (global)
request_templates — saved custom Graph request templates (global)
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

## API reference

All endpoints are under `/api/`. Request bodies are `application/json` unless noted. All `/api/` routes require a valid session cookie (set by `POST /api/auth/login`).

### Authentication

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/auth/login` | `{username, password}` → sets `session` HttpOnly cookie |
| `POST` | `/api/auth/logout` | Clears the session cookie |
| `GET` | `/api/auth/check` | Returns `{ok: true}` if authenticated |

### Campaigns

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/campaigns` | Array of all campaign objects |
| `POST` | `/api/campaigns` | `{name, description}` → 201 |
| `GET` | `/api/campaigns/{id}` | Campaign object |
| `GET` | `/api/campaigns/{id}/status` | Live counts |
| `POST` | `/api/campaigns/{id}/launch` | Start device code flow + polling |
| `POST` | `/api/campaigns/{id}/stop` | Cancel all polling |
| `GET` | `/api/campaigns/{id}/tokens` | Array of `TokenResult` |
| `GET` | `/api/campaigns/{id}/sessions` | Map of session snapshots |
| `GET` | `/api/campaigns/{id}/events` | SSE stream (JSON every 2s) |
| `GET` | `/api/campaigns/{id}/export` | Downloads evidence JSON |
| `DELETE` | `/api/campaigns/{id}` | Cascade delete |

### Targets

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/campaigns/{id}/targets/import` | `multipart/form-data` with `file`, or `text/plain` CSV body |
| `GET` | `/api/campaigns/{id}/targets` | Array of `Target` |
| `DELETE` | `/api/campaigns/{id}/targets/{targetId}` | Remove a single target |
| `POST` | `/api/campaigns/{id}/targets/{targetId}/launch` | Request device code for one target |
| `POST` | `/api/campaigns/{id}/targets/{targetId}/regen` | Regenerate code for one target |
| `POST` | `/api/campaigns/{id}/regen-all` | Regenerate all expired codes |

### Mail

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/campaigns/{id}/send-emails` | `{profile_id, template_id}` — bulk send |
| `POST` | `/api/campaigns/{id}/targets/{targetId}/send-email` | Per-target send |
| `GET` | `/api/campaigns/{id}/email-results` | Array of send results |

### QR phishing

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/campaigns/{id}/qr-emails` | `{profile_id, qr_template_id, dc_template_id, base_url, target_id?}` |
| `GET` | `/api/campaigns/{id}/qr-scans` | Array of confirmed scan events |
| `GET` | `/qr/{token}` | Public — serves `qrlanding.html` with the token injected |
| `POST` | `/qr/{token}/confirm` | Public — fired by the landing page; launches campaign, requests device code for the target, sends DC email, starts polling |

### Token management

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/campaigns/{id}/tokens/{targetId}/refresh` | Exchange refresh token → new pair |
| `GET` | `/api/campaigns/{id}/tokens/{targetId}/access-token` | Download `at_<upn>.txt` |
| `GET` | `/api/campaigns/{id}/tokens/{targetId}/refresh-token` | Download `rt_<upn>.txt` |
| `POST` | `/api/campaigns/{id}/tokens/{targetId}/exchange` | `{resource, scope, client_id, use_v1}` → token exchange |

### Graph Ops

All Graph Ops routes look up the stored access token for `{targetId}` and proxy to Microsoft Graph.

#### Identity

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `.../graph/{targetId}/me` | Current user profile |
| `POST` | `.../graph/{targetId}/users` | `{query?, top?}` — search users |
| `GET` | `.../graph/{targetId}/users/{userId}` | User detail |
| `GET` | `.../graph/{targetId}/users/{userId}/member-of` | User group memberships |
| `GET` | `.../graph/{targetId}/users/{userId}/batch` | Batch user attributes |
| `GET` | `.../graph/{targetId}/mailboxes` | All licensed member accounts |
| `GET` | `.../graph/{targetId}/auth-methods` | Registered auth methods |

#### Mail

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `.../graph/{targetId}/emails` | `{query, top?}` — search mailbox |
| `GET` | `.../graph/{targetId}/mail/folders` | List mail folders |
| `GET` | `.../graph/{targetId}/mail/messages` | List/page messages |
| `GET` | `.../graph/{targetId}/mail/messages/{msgId}` | Read single message |
| `POST` | `.../graph/{targetId}/mail/send` | Send new email |
| `POST` | `.../graph/{targetId}/mail/draft` | Create draft |
| `POST` | `.../graph/{targetId}/mail/messages/{msgId}/reply` | Reply |
| `POST` | `.../graph/{targetId}/mail/messages/{msgId}/forward` | Forward |
| `POST` | `.../graph/{targetId}/mail/messages/{msgId}/move` | Move to folder |
| `DELETE` | `.../graph/{targetId}/mail/messages/{msgId}` | Delete (soft) |
| `POST` | `.../graph/{targetId}/mail/messages/{msgId}/permanent-delete` | Permanent delete |
| `GET` | `.../graph/{targetId}/mail/messages/{msgId}/attachments` | List attachments |
| `GET` | `.../graph/{targetId}/mail/messages/{msgId}/attachments/{attId}` | Download attachment |
| `POST` | `.../graph/{targetId}/mail/messages/{msgId}/attach` | Add attachment |
| `POST` | `.../graph/{targetId}/mail/messages/{msgId}/send-draft` | Send draft |

#### OneDrive / SharePoint

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `.../graph/{targetId}/files` | `{query, top?}` — search files |
| `GET` | `.../graph/{targetId}/drive/ls` | `?item_id=` — list folder |
| `GET` | `.../graph/{targetId}/drive/download` | `?item_id=` — proxied file download |
| `POST` | `.../graph/{targetId}/drive/upload` | Upload file to drive |
| `DELETE` | `.../graph/{targetId}/drive/item` | Delete drive item |
| `GET` | `.../graph/{targetId}/drive/recent` | Recently accessed files |
| `GET` | `.../graph/{targetId}/drive/shared` | Files shared with the user |

#### Teams

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `.../graph/{targetId}/teams` | Joined teams |
| `GET` | `.../graph/{targetId}/teams/{teamId}/channels` | List channels |
| `GET` | `.../graph/{targetId}/teams/{teamId}/channels/{chanId}/messages` | Read channel messages |
| `POST` | `.../graph/{targetId}/teams/{teamId}/channels/{chanId}/messages` | Send channel message |
| `GET` | `.../graph/{targetId}/chats` | Direct + group chats |
| `GET` | `.../graph/{targetId}/chats/{chatId}/messages` | Read chat messages |
| `POST` | `.../graph/{targetId}/chats/{chatId}/messages` | Send chat message |
| `POST` | `.../graph/{targetId}/chats/create` | Create new chat |

#### Groups

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `.../graph/{targetId}/groups` | All tenant groups |
| `GET` | `.../graph/{targetId}/owned-groups` | Groups user owns |
| `GET` | `.../graph/{targetId}/groups/{groupId}` | Group details |
| `GET` | `.../graph/{targetId}/groups/{groupId}/members` | Direct members |
| `GET` | `.../graph/{targetId}/groups/{groupId}/transitive-members` | All nested members |
| `GET` | `.../graph/{targetId}/groups/{groupId}/owners` | Group owners |
| `GET` | `.../graph/{targetId}/groups/{groupId}/member-of` | Parent groups |
| `GET` | `.../graph/{targetId}/groups/{groupId}/drives` | Group SharePoint drives |
| `GET` | `.../graph/{targetId}/groups/{groupId}/sites` | Group SharePoint sites |
| `GET` | `.../graph/{targetId}/groups/{groupId}/app-roles` | App role assignments |
| `POST` | `.../graph/{targetId}/clone-group` | `{source_group_id, display_name, description?}` |

#### Apps and policies

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `.../graph/{targetId}/apps` | App registrations + service principals |
| `GET` | `.../graph/{targetId}/grants` | OAuth2 delegated permission grants |
| `POST` | `.../graph/{targetId}/deploy-app` | `{display_name, redirect_uri?, scopes?}` |
| `GET` | `.../graph/{targetId}/conditional-access` | CA policies (requires Policy.Read.All) |

#### Search and custom

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `.../graph/{targetId}/search` | M365 cross-resource search |
| `POST` | `.../graph/{targetId}/custom` | Arbitrary Graph API request |

#### MFA (via campaign target)

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `.../graph/{targetId}/mfa/methods` | List registered MFA methods |
| `POST` | `.../graph/{targetId}/mfa/session` | Get My Sign-ins session context |
| `POST` | `.../graph/{targetId}/mfa/add-phone` | `{phone_type, phone_number}` |
| `POST` | `.../graph/{targetId}/mfa/add-email` | `{email}` |
| `POST` | `.../graph/{targetId}/mfa/add-app` | `{app_type, secret_key?}` |
| `POST` | `.../graph/{targetId}/mfa/register-totp` | Register TOTP + returns secret/QR |
| `POST` | `.../graph/{targetId}/mfa/verify` | `{verification_id, code}` |
| `POST` | `.../graph/{targetId}/mfa/delete` | `{method_id}` |
| `POST` | `.../graph/{targetId}/mfa/fido2/begin` | `{key_name}` |
| `POST` | `.../graph/{targetId}/mfa/fido2/complete` | `{verification_id, attestation_response}` |

### Device certificates

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/device-certs` | List all stored device certs |
| `POST` | `/api/device-certs` | Register a new virtual device |
| `POST` | `/api/device-certs/import` | Import existing cert (PEM + key) |
| `DELETE` | `/api/device-certs/{id}` | Delete a device cert |

### Primary Refresh Tokens

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/prts` | List all stored PRTs |
| `POST` | `/api/prts/request` | `{campaign_id, target_id, device_cert_id, client_id}` |
| `POST` | `/api/prts/import` | Import a raw PRT |
| `DELETE` | `/api/prts/{id}` | Delete a PRT |
| `POST` | `/api/prts/{id}/access-token` | `{resource, scope, client_id}` → access token |
| `GET` | `/api/prts/{id}/cookie` | PRT → SSO cookie |

### Windows Hello keys

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/winhello-keys` | List registered keys |
| `POST` | `/api/winhello-keys` | `{device_cert_id, campaign_id, target_id, label}` |
| `DELETE` | `/api/winhello-keys/{id}` | Delete |

### OTP secrets

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/otp-secrets` | List all stored TOTP secrets |
| `POST` | `/api/otp-secrets` | `{label, secret}` — add a secret |
| `GET` | `/api/otp-secrets/{id}/code` | Generate current TOTP code |
| `DELETE` | `/api/otp-secrets/{id}` | Delete |

### Utilities

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/util/tenant-lookup` | `{domain}` → tenant ID via OIDC metadata |

### Webhook listener

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/receive` | Always-on endpoint — logs any `application/json` or `application/json-raw` payload to `webhook_log_path` |
| `GET` | `/api/webhook/status` | `{running, port, log_path, entries}` |
| `POST` | `/api/webhook/start` | `{port: N}` — bind standalone listener on port N; returns error immediately if port is unavailable |
| `POST` | `/api/webhook/stop` | Graceful shutdown (5s timeout) |
| `GET` | `/api/webhook/logs` | Last 100 entries as `{entries, total}` |

### Sender profiles

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/mailer/profiles` | Array of profiles |
| `POST` | `/api/mailer/profiles` | `{name, host, port, username, password, from_name, from_address, implicit_tls}` |
| `DELETE` | `/api/mailer/profiles/{id}` | — |
| `POST` | `/api/mailer/profiles/{id}/test` | `{to}` — sends a test email |

### Email templates

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/mailer/templates` | Array of templates |
| `POST` | `/api/mailer/templates` | `{name, subject, html_body, text_body?, redirector_url?}` |
| `PUT` | `/api/mailer/templates/{id}` | Full replace |
| `DELETE` | `/api/mailer/templates/{id}` | — |

---

## Artifacts and evidence

Artifact files are written to `storage.artifacts_path/<campaign_id>/` with mode `0600`.

| File | Written when | Contents |
|------|-------------|----------|
| `device_codes.json` | Campaign launch | All `DeviceCodeResponse` objects per target |
| `token_<targetID>_<nanoseconds>.json` | Each token capture | Single `TokenResult` with all tokens and timestamps |

The primary evidence package is the JSON export from `GET /api/campaigns/{id}/export`.

---

## Post-exploitation (Graph Ops)

The **Graph Ops** tab provides built-in post-exploitation capabilities against captured tokens. All operations run server-side and display results in formatted tables. A **{ } Raw JSON** toggle shows the raw API response; **↓ Download JSON** saves results to disk.

### What the tokens grant

The default scope (`https://graph.microsoft.com/.default offline_access openid profile`) grants delegated access to everything the target can access:

- Read, send, reply, forward, delete email; download attachments
- Browse and download OneDrive/SharePoint files; upload and delete
- Read and send Teams chats and channel messages
- Enumerate Azure AD users, groups, roles, and their memberships
- Read app registrations, service principals, and OAuth2 consent grants
- Create app registrations (if the user has permission)
- Dump conditional access policies (admin tokens)
- Cross-resource M365 search

The `offline_access` scope ensures a `refresh_token` is issued. Token exchange (`/api/campaigns/{id}/tokens/{targetId}/exchange`) can mint access tokens for any Microsoft service — SharePoint, Azure Management, Key Vault, and more.

---

## Webhook listener

**Built-in endpoint (`POST /receive`)** — always available on the main ENTRAITH port. Accepts any JSON payload; logs to `webhook_log_path`.

**Standalone listener** — a secondary HTTP server on a configurable port, started from the **Webhook Listener** panel in the Infrastructure page. Enter the desired port (default 9000) and click **Start**. Accepts POST requests on **any path** so the callback URL on the target side can be arbitrary. The port is bound synchronously — if the port is already in use, an error is returned immediately.

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

The **Webhook Listener** panel polls `GET /api/webhook/logs` and renders the last 100 entries as formatted cards showing timestamp, source IP, HTTP method, path, and syntax-highlighted JSON payload.

---

## Legal

For authorized security assessments only. You must have explicit written permission from the target organisation before running this tool against their users or infrastructure. Unauthorized use is illegal and unethical.
