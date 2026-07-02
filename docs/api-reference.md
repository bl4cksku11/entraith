# API Reference

## API reference

All endpoints are under `/api/`. Request bodies are `application/json` unless noted. Every `/api/` route requires a valid session cookie (set by `POST /api/auth/login`), and so do the `/webhook/*` control endpoints below. The only unauthenticated endpoints are the target-facing ones: `/login`, `/qr/*`, `/intune/*`, `/receive`, and `/capture`.

### Authentication

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/auth/login` | `{username, password}` → sets `session` HttpOnly cookie; returns `{status, username, role, must_change_password}`. Returns `429` with a `Retry-After` header once the login rate limit trips |
| `POST` | `/api/auth/logout` | Clears the session cookie |
| `GET` | `/api/auth/check` | Returns `{ok, username, role, must_change_password}` |
| `POST` | `/api/auth/change-password` | `{new_password}` — clears `must_change_password` flag for current user |

### User management (admin only)

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/users` | List all user accounts |
| `POST` | `/api/users` | `{username, password, role}` — create user; `role` is `admin` or `operator` |
| `PUT` | `/api/users/{id}` | `{username?, role?}` — update user fields |
| `DELETE` | `/api/users/{id}` | Delete a user account |
| `POST` | `/api/users/{id}/reset-password` | Generate a new random password; user must change on next login |

### Campaigns

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/campaigns` | Array of all campaign objects |
| `POST` | `/api/campaigns` | `{name, description}` → 201 |
| `GET` | `/api/campaigns/{id}` | Campaign object |
| `PATCH` | `/api/campaigns/{id}` | `{name?, description?}` — rename/update campaign fields |
| `POST` | `/api/campaigns/{id}/duplicate` | Clone campaign + targets (no tokens); returns new campaign |
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

### Intune phishing

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/campaigns/{id}/intune-emails` | `{profile_id, intune_template_id, base_url, target_id?}` — send Intune phishing emails |
| `GET` | `/api/campaigns/{id}/intune-captures` | Array of captured Intune flow events |
| `GET` | `/intune/{token}` | Public — serves `intunelanding.html` with the token injected |
| `POST` | `/intune/capture` | Public — fired by the landing page; logs capture event (source IP, trigger, campaign, target) |

### Token management

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/campaigns/{id}/tokens/{targetId}/refresh` | Exchange refresh token → new pair |
| `GET` | `/api/campaigns/{id}/tokens/{targetId}/access-token` | Download `at_<upn>.txt` |
| `GET` | `/api/campaigns/{id}/tokens/{targetId}/refresh-token` | Download `rt_<upn>.txt` |
| `POST` | `/api/campaigns/{id}/tokens/{targetId}/exchange` | `{resource, scope, client_id, use_v1}` → token exchange |
| `POST` | `/api/campaigns/{id}/tokens/{targetId}/exchange-refresh` | Refresh a previously exchanged token |

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

#### Persistence modules (mutating — logged in the deployment ledger)

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `.../graph/{targetId}/ca-exclusion` | `{display_name, exclude_user_id, state?}` — CA policy excluding the operator |
| `POST` | `.../graph/{targetId}/add-app-password` | `{app_object_id, display_name?}` — SP credential backdoor (secret shown once) |
| `POST` | `.../graph/{targetId}/add-app-key` | `{app_object_id, display_name?}` — SP cert backdoor (Regla #3; private key shown once) |
| `POST` | `.../graph/{targetId}/assign-app-role` | `{resource_sp_id, principal_id, app_role_id}` — grant an application permission |
| `POST` | `.../graph/{targetId}/assign-directory-role` | `{principal_id, role_definition_id, directory_scope_id?}` — assign a directory role |
| `GET` | `.../graph/{targetId}/find-sp` | `?appId=` — resolve a service principal by appId (defaults to Microsoft Graph) |

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

### Deployment ledger / teardown

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/artifacts` | List all deployed-artifact ledger entries |
| `GET` | `/api/campaigns/{id}/artifacts` | List a campaign's deployed artifacts |
| `POST` | `/api/artifacts/{artId}/rollback` | Revert one artifact (Graph-kind auto; else returns `skipped_manual`) |
| `POST` | `/api/campaigns/{id}/teardown` | Revert all auto-revertible artifacts newest-first; returns `{rolled_back, failed, skipped_manual, results}` |

### OTP secrets

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/otp-secrets` | List all stored TOTP secrets |
| `POST` | `/api/otp-secrets` | `{label, secret}` — add a secret |
| `GET` | `/api/otp-secrets/{id}/code` | Generate current TOTP code |
| `DELETE` | `/api/otp-secrets/{id}` | Delete |

### Request templates

Saved custom Graph API request templates (stored globally, used in the custom request builder in Advanced Tools).

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/request-templates` | List all saved request templates |
| `POST` | `/api/request-templates` | `{label, method, url, body?}` — save a template |
| `DELETE` | `/api/request-templates/{id}` | Delete a template |

### Utilities

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/util/tenant-lookup` | `{domain}` → tenant ID via OIDC metadata |

### Webhook listener

`/receive` and `/capture` are public so beacons and broker callbacks can reach them. The `/webhook/*` control endpoints require an operator session.

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| `POST` | `/receive` | public | Always-on receiver. Logs any `application/json` or `application/json-raw` payload to the webhook log |
| `POST` | `/capture` | public | Native Broker Interop. Targets POST a captured URI here; the broker URI is parsed and written to the webhook log as a `broker_capture` entry |
| `GET` | `/webhook/status` | session | `{running, port, log_path, entries}` |
| `POST` | `/webhook/start` | session | `{port: N}` — bind the standalone listener on port N; returns an error immediately if the port is unavailable |
| `POST` | `/webhook/stop` | session | Graceful shutdown (5s timeout) |
| `GET` | `/webhook/logs` | session | Last 100 entries as `{entries, total}` |

The webhook log file is `stream_monitor.log` under `storage.artifacts_path`.

### Token listener

A standalone OAuth-token intake server that ingests tokens (from an AiTM proxy, phishing page, or manual drop) into a campaign. The **intake endpoint runs on its own port** (default 8000) and is unauthenticated by design; the `/api/token-listener/*` control endpoints require an operator session. See [configuration.md](configuration.md#token-listener) for the payload format.

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| `POST` | `/token` (intake port) | public | Ingest one token. JSON or form-urlencoded. Body: `access_token`/`refresh_token`/`id_token` (≥1), `campaign_id`, `target_id`/`target_email`, `token_type`, `expires_in`, `scope`, `source`. Returns `{status:"ingested", campaign_id, target_id, target_email, upn}` |
| `GET`  | `/health` (intake port) | public | `{status:"ok"}` |
| `GET`  | `/api/token-listener/status` | session | `{running, port, started_at, received, ingested, log_path, default_campaign, default_port}` |
| `POST` | `/api/token-listener/start` | session | Optional `{port, default_campaign}`. Port falls back to `listener.token_port` (8000). A supplied `default_campaign` must exist |
| `POST` | `/api/token-listener/stop` | session | Graceful shutdown (5s timeout) |
| `GET`  | `/api/token-listener/logs` | session | `{entries, status}` — last 100 redacted `token_ingest` entries |

The token listener log file is `token_listener.log` under `storage.artifacts_path`. Token material is redacted in the log.

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

