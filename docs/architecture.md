# Architecture & Code Structure

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  cmd/entraith/main.go                                                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐ │
│  │ campaigns.      │  │  mailer.Manager  │  │  api.Handler            │ │
│  │ Manager         │  │  (profiles,      │  │  (HTTP routes,          │ │
│  │ (campaigns,     │  │   templates)     │  │   wires managers,       │ │
│  │  polling)       │  │                  │  │   session auth)         │ │
│  └──────┬──────────┘  └────────┬─────────┘  └─────────────────────────┘ │
│         └──────────────────────┘                                        │
│                    ▼                                                    │
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
│           │  qr_scans       │  ← confirmed QR scan events               │
│           │  intune_tokens  │  ← per-target Intune phishing tokens      │
│           │  intune_captures│  ← captured Intune OAuth flows            │
│           │  users          │  ← operator accounts (role, pw change)    │
│           └─────────────────┘                                           │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  devicecode.Engine  (per campaign, in-memory only)              │   │
│   │  - one goroutine per target for polling                         │   │
│   │  - jittered sleep intervals                                     │   │
│   │  - spoofed User-Agent                                           │   │
│   │  - Results chan → collectResults goroutine                      │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  graph.Client  (stateless, per Graph Ops request)               │   │
│   │  - email browse/send/reply/forward, folder navigation           │   │
│   │  - OneDrive/SharePoint browse, download, upload, delete         │   │
│   │  - Teams chats, channels, messages, send                        │   │
│   │  - user/group enumeration with deep group inspection            │   │
│   │  - app registrations, service principals, OAuth2 grants         │   │
│   │  - conditional access policies, auth methods                    │   │
│   │  - M365 cross-resource search                                   │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  Advanced modules (Advanced Tools page)                         │   │
│   │  mfa         — list/add/delete MFA methods, register TOTP/FIDO2 │   │
│   │  devicereg   — virtual device registration (AAD Join / WPJOIN)  │   │
│   │  prt         — Primary Refresh Token request and conversion     │   │
│   │  tokenexchange — v1/v2 token exchange, cross-resource tokens    │   │
│   └─────────────────────────────────────────────────────────────────┘   │
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
│   │   └── auth.go              # Password hashing (argon2id, legacy SHA-256 verified for migration), token generation
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
│   │                            # SendIntuneEmails (Intune OAuth phishing flow)
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
│   │   │                        # Auth (RBAC: admin / operator), user management,
│   │   │                        # campaigns, targets, Graph Ops, MFA, Intune phishing,
│   │   │                        # device certs, PRTs, WinHello, OTP, token exchange
│   │   └── webhook.go           # Standalone webhook listener goroutine
│   │                            # Start/stop/log the secondary HTTP listener
│   │
│   └── web/
│       ├── pages.go             # go:embed declarations for all HTML files
│       ├── login.html           # Login page (public, session cookie auth)
│       ├── dashboard.html       # Operations console (SPA — campaigns, mail,
│       │                        # Graph Ops, QR phishing, Intune phishing, webhook broker)
│       ├── tools.html           # Advanced Tools (MFA, device reg, PRT, token exchange)
│       ├── infra.html           # Infrastructure page (sender profiles, templates)
│       ├── qrlanding.html       # QR scan landing page — editable; served to targets
│       │                        # on GET /qr/{token}; fires confirm POST on load
│       └── intunelanding.html   # Intune phishing landing page — Microsoft-lookalike;
│                                # served to targets on GET /intune/{token}; captures
│                                # ms-appx-web:// OAuth flow trigger
│
├── bootstrap/
│   ├── engagement.example.conf  # Example key=value config
│   └── targets.example.csv      # Example target list
│
└── etemplates/                  # Example email templates
    ├── email-template.html      # Standard device code email
    ├── template-devicecode.html # Alternative device code template
    ├── template-intune.html     # Intune phishing email template
    └── template-qr.html         # QR phishing email template
```

### Package responsibilities

**`auth`** — password hashing (`argon2id`, with transparent verification of legacy `SHA-256` hashes for migration), constant-time password verification, random password generation, and cryptographically random session token generation. Used by `main.go` to create the first-run admin user and by `api` for login/logout.

**`config`** — loads a flat `key=value` config file (comments with `#`, inline comments stripped). Sets safe defaults for missing values. No external dependencies.

**`store`** — the SQLite persistence layer (`modernc.org/sqlite`, pure Go, no CGO). Opened once at startup and shared by both managers. Schema applied via `CREATE TABLE IF NOT EXISTS` on every startup (idempotent). Foreign keys with `ON DELETE CASCADE` cascade deletes from campaigns to all associated rows. Stores sessions (operator login), device certificates, PRTs, Windows Hello keys, OTP secrets, QR scan events, Intune phishing tokens and captures, and multi-operator user accounts in addition to campaign data.

**`ledger`** — the deployment ledger. Records every mutation Entraith pushes into a target tenant (app registration, cloned group, injected MFA method, registered device, Windows Hello key, CA policy, SP credential, role assignment) as a `deployed_artifacts` row carrying a rollback descriptor, the audit signature it triggers, and a secret-by-reference pointer. `Teardown(ctx, artifacts, rollbacker)` walks artifacts newest-first and undoes the auto-revertible (Graph-kind) ones, surfacing DRS/session-bound ones for manual cleanup. Turns memory-dependent cleanup into a guaranteed, auditable engagement teardown.

**`campaigns`** — owns the `Manager` (map of campaigns, mutex-protected). Each `Campaign` holds a `*targets.Store`, a `*devicecode.Engine`, result slices, email send results, and a buffered `notify` channel for instant SSE pushes. `Manager.Load()` reads all campaigns from SQLite at startup. `Manager.Launch` orchestrates the device code flow. `Manager.SendQREmails` handles bulk or per-target QR phishing email dispatch. `Manager.SendIntuneEmails` sends Intune OAuth phishing emails with unique per-target landing page tokens. `Manager.NotifySSE` wakes any open SSE connections for a campaign immediately.

**`devicecode`** — the core engine. One `Engine` per campaign (in-memory only). Holds a `map[targetID]*Session`. Each `Session` carries a `cancel context.CancelFunc` — if a target scans a QR code a second time, the old polling goroutine is cancelled before a new session is stored, preventing stale polling of the invalidated code. `StartPolling` spawns one goroutine per target with a per-session child context. Results delivered via buffered channel. All requests use a consistent, spoofed User-Agent. The standalone `RefreshAccessToken` exchanges a `refresh_token` for a new pair.

**`graph`** — stateless Graph API client. `graph.New(accessToken)` wraps a Bearer token and exposes methods for every supported post-exploitation operation. All methods accept a `context.Context`. Covers full mail operations (browse folders, read/send/reply/forward/delete/attach), OneDrive (list, download, upload, delete, recent, shared), Teams (teams, channels, chats, messages, create chat, send), groups (info, members, transitive members, owners, drives, sites, app roles), users (info, member-of, batch), apps, grants, conditional access, auth methods, and M365 cross-resource search. Also exposes the mutating persistence operations — `CreateConditionalAccessPolicy`, `AddAppPassword` (SP credential backdoor), `AssignAppRole`, `AssignDirectoryRole`, `GetServicePrincipalByAppID` — and `RollbackCall`, a generic authenticated DELETE/PATCH used by the deployment-ledger teardown to undo deployed artifacts.

**`mfa`** — client for the My Sign-ins API (`mysignins.microsoft.com`). Requires an access token scoped to resource `19db86c3-b2b9-44cc-b339-36da233a3be2` (obtained automatically by exchanging the captured refresh token). Supports listing, adding, and deleting MFA methods; TOTP registration (with server-side `GenerateTOTP` for live code display); and FIDO2 key registration flow.

**`devicereg`** — registers a virtual device with Entra ID. Generates an RSA-2048 keypair and self-signed certificate, then submits a device registration request to `enterpriseregistration.windows.net`. Supports both AAD Join (`JoinTypeAADJoined`) and Workplace Join (`JoinTypeRegistered`). The resulting `DeviceCert` is required for PRT operations.

**`prt`** — Primary Refresh Token operations. `Request(ctx, refreshToken, clientID, dc)` uses the device cert to request a PRT from the v1.0 token endpoint via a signed JWT. `ToAccessToken` converts a PRT to an access token for any resource using HMAC-SHA256 signed JWTs and an encrypted request. `ToCookie` converts a PRT to a browser SSO cookie. `RegisterWinHello` registers a Windows Hello for Business NGC key bound to the device.

**`tokenexchange`** — exchanges a refresh token for an access token targeting a different resource or scope. Supports both v1.0 (`resource` parameter) and v2.0 (`scope` parameter) endpoints. `LookupTenantID` resolves a domain to its Entra tenant ID via the OIDC metadata endpoint.

**`targets`** — thread-safe in-memory store. Deduplicates by lowercase email. CSV import with flexible column detection (only `email` required). IDs are 8-byte random hex strings.

**`mailer`** — stateless send logic plus an in-memory manager for profiles and templates. Persistence injected by `main.go` via `SetPersistence(...)` callbacks. `Render` performs simple string replacement. `buildMIME` constructs RFC 5322 messages with per-message random `Message-ID` and MIME boundary from `crypto/rand`.

**`api`** — `Handler` holds pointers to all managers. `Routes()` returns a configured `*http.ServeMux` with all endpoints. Handles auth (login/logout/check/change-password), RBAC-gated user management (admin vs. operator), all campaign operations, Graph Ops, MFA, device certs, PRTs, Windows Hello, OTP secrets, token exchange, the deployment ledger and one-click teardown, webhook management, public QR scan endpoints (`GET /qr/{token}`, `POST /qr/{token}/confirm`), and public Intune phishing endpoints (`GET /intune/{token}`, `POST /intune/capture`). The SSE handler (`streamEvents`) pushes an initial snapshot on connect and reacts to both the 2-second ticker and the campaign's `notify` channel.

**`web`** — five embedded HTML files (`go:embed`). No external JS dependencies. All pages communicate exclusively via the REST API and SSE for live updates. `qrlanding.html` is public-facing and served to targets who scan a QR code — it fires a background confirm POST then redirects. Operator sessions are enforced server-side by `pageGuard` in `main.go` — unauthenticated requests are redirected to `/login?next=<path>`.

---

