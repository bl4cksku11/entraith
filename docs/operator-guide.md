# Operator Guide

## Operator workflow

A campaign moves through draft, launch, send, monitor, export, delete. The steps below are the normal device-code flow. QR and Intune modes replace steps 4 and 5; see their sections.

### Step 1: Create a campaign

Enter a name and an optional description in the sidebar and click **Create Campaign**. This writes a `Campaign` row with status `draft`.

### Step 2: Import targets

Upload a CSV or paste addresses. The only required column is `email`. Optional columns are `display_name`, `department`, `region`, `group`, `custom_field`. Duplicate addresses are skipped.

```csv
email,display_name,department,region,group
jsmith@corp.com,John Smith,Finance,US-East,executives
mary.jones@corp.com,Mary Jones,Finance,US-East,finance
```

Pasting takes one email per line and is converted to a minimal CSV before import.

### Step 3: Configure mail

Open **Infrastructure** in the top nav to set up sender profiles and email templates. Both are global: they outlive individual campaigns and survive restarts.

### Step 4: Launch the campaign

Click **▶ Launch Campaign**. For each target the server:

1. Calls `Engine.RequestDeviceCode()`, which POSTs to the Microsoft device-code endpoint.
2. Waits a random 800ms to 3s before the next request.
3. Writes the device code to the database and to `artifacts/{campaign_id}/device_codes.json`.
4. Calls `Engine.StartPolling()`, one goroutine per target, polling at the configured interval with 30% jitter.
5. Writes each captured token to the database immediately, via the `collectResults` goroutine.

### Step 5: Send phishing emails

Pick a **Sender Profile** and an **Email Template**, then click **✉ Send Phishing Emails** to send a personalized device-code email to every target. The **→** button on a Sessions row sends to a single target.

Sending is kept separate from launch on purpose. Launch first so the polling clock is running, then send.

### Step 6: Phishing mode (alternative to steps 4 and 5)

The **Phishing Mode** dropdown in the sidebar picks the delivery method:

- **Normal** (default): launch the campaign, then send emails carrying the user code.
- **QR**: send QR emails. The campaign launches by itself when a target scans. See [QR phishing](#qr-phishing).
- **Intune Phishing**: send a link to an operator-hosted page that mimics Microsoft's device enrollment. See [Intune phishing](#intune-phishing).

### Step 7: Monitor

You can keep several campaigns open at once as **tabs** above the campaign view. Each tab holds its own SSE connection and pagination. Switching tabs saves and restores that campaign's state; closing a tab drops its SSE connection.

The **Sessions** tab updates live over SSE (`/api/campaigns/{id}/events`). The first snapshot arrives on connect. After that, updates come every 2 seconds, and immediately whenever something happens (a code email is sent, a token is captured, the campaign launches). The sidebar status badge tracks the same stream. A captured token lands in **Captured Tokens** with a flash.

### Step 8: Token management

Each row in **Captured Tokens** offers:

- **↓ AT**: download the raw access token as `at_<upn>.txt`.
- **↓ RT**: download the raw refresh token as `rt_<upn>.txt`.
- **↺ Refresh**: trade the stored refresh token for a new pair and update the database.

### Step 9: Post-exploitation (Graph Ops)

Open the **Graph Ops** tab and pick a captured target from the dropdown. The full set of operations is in [Post-exploitation](#post-exploitation-graph-ops).

### Step 10: Advanced operations

**Advanced Tools** covers MFA manipulation, device registration, PRT operations, and token exchange. See [Advanced Tools](advanced-tools.md).

### Step 11: Export evidence

Click **↓ Export Campaign** to download `campaign_<id>_export.json`. It holds the campaign metadata, every target, the device codes, the tokens, and the email results.

### Step 12: Delete when done

Click **🗑 Delete Campaign**. After you confirm, the campaign and everything tied to it are deleted through `ON DELETE CASCADE`. Export first.

---


## QR phishing

QR delivery wraps the device-code flow in a scannable code. Reach for it when the target will authenticate on a phone, or when email scanners would flag a direct Microsoft link.

### How it works

The flow is two-phase. Nothing is requested from Microsoft until the target scans; the device code is issued on demand at scan time.

1. Send a **QR email** from the **QR Phishing** section. It carries the QR image. No launch or pre-issued codes are needed. Each target shows up in Sessions right away with state `qr_sent`.
2. The QR encodes a per-target URL on your infrastructure: `<base_url>/qr/<token>`.
3. When the target scans, `GET /qr/<token>` serves the landing page (`qrlanding.html`). It fires a background `POST /qr/<token>/confirm` and redirects the target to `microsoft.com/devicelogin`.
4. On that confirm POST, Entraith launches the campaign if it isn't running, requests a fresh device code for that target (cancelling the old polling goroutine first if they scanned before), sends the **DC email** with the user code, and starts polling. The session moves from `qr_sent` to `pending`.
5. The target is now on the real Microsoft login page, gets the DC email seconds later, enters the code, and authenticates. The token is captured.

### Customizing the landing page

The page is embedded from `internal/web/qrlanding.html`. Edit the logo, text, and colors, then rebuild:

```bash
go build -o entraith ./cmd/entraith
```

Leave the `fetch('/qr/{{TOKEN}}/confirm', ...)` call in the `<script>` block alone. That call is what registers the scan and triggers the code email. The server fills in `{{TOKEN}}` at request time.

The redirect at the end of the script (`window.location.replace(...)`) decides where the target lands. Default is `https://microsoft.com/devicelogin`.

### Template placeholders

| Placeholder | Resolved to |
|-------------|-------------|
| `{{QRC}}` | Base64-encoded PNG of the QR code for this target's redirect URL |

Use it in an `<img>` tag:

```html
<img src="data:image/png;base64,{{QRC}}" alt="QR Code" width="200" height="200">
```

The **DC email template** uses the standard `{{DCODE}}`, `{{URL}}`, `{{EMAIL}}`, `{{NAME}}` placeholders. It's the fallback code email that goes out automatically when the target scans.

### Sending

In the **QR Phishing** section of the Operations sidebar (shown when **Phishing Mode** is **QR**):

1. Pick a **Sender Profile**, a **QR email template**, and a **DC email template**.
2. Set the **Public Base URL** (for example `https://r.yourdomain.com`), the host where your `/qr/<token>` endpoint answers.
3. Click **⬛ Send QR Emails**. The DC email is sent at scan time, so there's no manual second step.

> Do not launch the campaign before sending QR emails. The launch happens on the first scan of each target's code.

### QR scan tracking

After you send QR emails, targets sit in **Sessions** with state `qr_sent`, which confirms delivery before any scan. A scan moves the session to `pending` and starts polling.

The **QR Scans** tab logs every confirmed scan: timestamp, source IP, and which target's code fired. Each entry maps to a successful `POST /qr/{token}/confirm`. The full log is at `GET /api/campaigns/{id}/qr-scans`.

---


## Intune phishing

This mode pairs the phishing email with a Microsoft-lookalike device enrollment page. Use it when the target org runs Intune and a device-enrollment pretext is believable.

### How it works

1. Send **Intune phishing emails** from the **Intune Phishing** section (shown when **Phishing Mode** is **Intune Phishing**). Each email carries a per-target link to `<base_url>/intune/<token>`.
2. When the target clicks, `GET /intune/<token>` serves `intunelanding.html`, styled like Microsoft's account sign-in.
3. When the target interacts (submits their email, or clicks Next), the page fires `POST /intune/capture` in the background. Entraith logs the source IP, the trigger event, the campaign, and the target.
4. The page then redirects to the real Microsoft Intune OAuth URL (`ms-appx-web://` via the Microsoft.AAD.BrokerPlugin), finishing the enrollment pretext.

### Captured data

Each capture lands in the `intune_captures` table, readable at `GET /api/campaigns/{id}/intune-captures`. The fields are `campaign_id`, `target_id`, `token`, `source_ip`, `trigger` (the event that fired the capture), `url`, `timestamp`, and `raw_json` (the full POST body).

### Customizing the landing page

The page is embedded from `internal/web/intunelanding.html`. Edit the logo, text, and form fields, then rebuild:

```bash
go build -o entraith ./cmd/entraith
```

Leave the `fetch('/intune/capture', ...)` call in the `<script>` block alone; it's what registers the interaction. The server fills in `{{TOKEN}}` at request time.

### Template placeholders

| Placeholder | Resolved to |
|-------------|-------------|
| `{{URL}}` | The full Intune landing URL for this target (`<base_url>/intune/<token>`) |
| `{{EMAIL}}` | Target's email address |
| `{{NAME}}` | Target's display name from the CSV |

### Sending

In the **Intune Phishing** section of the Operations sidebar:

1. Pick a **Sender Profile** and an **Intune email template**.
2. Set the **Public Base URL** (for example `https://r.yourdomain.com`).
3. Click **Send Intune Emails** to hit every target, or use the **→** button on a row for one.

---


## Mail system

### Sender profiles

| Field | Notes |
|-------|-------|
| `name` | Internal label |
| `host` | SMTP hostname |
| `port` | `587` (STARTTLS) or `465` (implicit TLS) |
| `username` | SMTP auth username |
| `password` | SMTP auth password. Encrypted at rest |
| `from_name` | Display name in the `From:` header |
| `from_address` | Sender email address |
| `implicit_tls` | `true` for TLS-on-connect (port 465), `false` for STARTTLS |
| `auth_method` | Force the SMTP AUTH mechanism: `plain` (default) or `login`. Exchange and Outlook hosts are detected automatically |

```
Office365:  host: smtp.office365.com  port: 587  implicit_tls: false
Gmail:      host: smtp.gmail.com      port: 587 or 465
```

Use **Test Send** to confirm SMTP works before a live campaign.

### Template placeholders

| Placeholder | Resolved to |
|-------------|-------------|
| `{{DCODE}}` | Target's user code, for example `ABCD-EFGH` |
| `{{URL}}` | Redirector URL if set, otherwise the real Microsoft verification URI |
| `{{REALURL}}` | Always `https://microsoft.com/devicelogin` |
| `{{EMAIL}}` | Target's email address |
| `{{NAME}}` | Target's display name from the CSV |
| `{{QRC}}` | Base64 PNG of the QR code (QR templates only) |

### Redirector URL

Set a **Redirector URL** on the template so links point at your infrastructure instead of `microsoft.com` directly. `{{URL}}` then resolves to the redirector, while `{{REALURL}}` always resolves to the real Microsoft URL.

### MIME construction

Every email is a proper RFC 5322 `multipart/alternative` message:

- `Message-ID`: 16 bytes from `crypto/rand`, scoped to the sender's domain.
- `Date`: the actual send time, in RFC 5322 format.
- MIME boundary: 12 bytes from `crypto/rand`, per message.
- No `X-Mailer`, `X-Originating-IP`, or other tool-identifying headers.

---


## Post-exploitation (Graph Ops)

The **Graph Ops** tab runs post-exploitation against captured tokens. Everything runs server-side and renders into tables. **{ } Raw JSON** shows the raw API response; **↓ Download JSON** saves results to disk.

### What the tokens grant

The default scope (`https://graph.microsoft.com/.default offline_access openid profile`) gives delegated access to everything the target can reach:

- Read, send, reply, forward, and delete email; download attachments.
- Browse, download, upload, and delete OneDrive and SharePoint files.
- Read and send Teams chats and channel messages.
- Enumerate users, groups, roles, and their memberships.
- Read app registrations, service principals, and OAuth2 consent grants.
- Create app registrations, if the user can.
- Dump conditional access policies, with an admin token.
- Run cross-resource M365 search.

The `offline_access` scope is what gets you a refresh token. Token exchange (`/api/campaigns/{id}/tokens/{targetId}/exchange`) mints access tokens for other Microsoft services: SharePoint, Azure Management, Key Vault, and the rest.

---


## Artifacts and evidence

Artifact files go under `storage.artifacts_path/<campaign_id>/`, mode `0600`.

| File | Written when | Contents |
|------|-------------|----------|
| `device_codes.json` | Campaign launch | Every `DeviceCodeResponse`, one per target |
| `token_<targetID>_<nanoseconds>.json` | Each token capture | One `TokenResult` with all tokens and timestamps |

The main evidence package is the JSON export at `GET /api/campaigns/{id}/export`.
