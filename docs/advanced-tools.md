# Advanced Tools

The **Advanced Tools** page (`/tools`) handles post-capture operations that go past plain Graph API access. Everything here is reachable from the top navigation.

## MFA manipulation

Needs an access token scoped to the My Sign-ins API. Entraith exchanges the target's captured refresh token for you when you pick a target in any MFA operation.

| Operation | What it does |
|-----------|-------------|
| **List Methods** | Lists every registered MFA method (phone, email, authenticator app, FIDO2, and so on) |
| **Add Phone** | Registers a mobile or office number as an MFA method |
| **Add Email** | Registers an email address as an MFA method |
| **Add Authenticator App (TOTP)** | Registers your authenticator as a new TOTP app and shows the live code |
| **Add Authenticator App (push)** | Registers a push-only or push+OTP authenticator |
| **Verify Method** | Finishes verification of a method you just added |
| **Delete Method** | Removes a registered MFA method |
| **FIDO2 Registration** | Runs the FIDO2 security-key registration, start to finish |

TOTP secrets live in the `otp_secrets` table and are encrypted at rest. Generate the current code at `GET /api/otp-secrets/{id}/code`.

## Device registration

Registers a virtual device with Entra ID using the captured user's access token. The device certificate it produces is what PRT operations need.

| Field | Notes |
|-------|-------|
| **Label** | Friendly name for the cert, for your own reference |
| **Device type** | `Windows`, `iOS`, `Android`, `MacOS` |
| **Join type** | `AAD Join` (domain-joined) or `Workplace Join` (BYOD/registered) |
| **Target domain** | For example `corp.com`. Goes into the cert CN |
| **OS version** | For example `10.0.19045.0` |

Entraith builds an RSA-2048 keypair and a self-signed cert locally, then submits the registration to `enterpriseregistration.windows.net`. The cert and private key go into the database (the private key encrypted at rest) and back the PRT requests that follow.

## Primary Refresh Token (PRT)

A PRT is a device-bound token. Bound to a device cert, it survives a password reset, mints access tokens for any resource, and produces browser SSO cookies.

| Operation | What it does |
|-----------|-------------|
| **Request PRT** | Trades a captured refresh token plus a device cert for a PRT, via the v1.0 token endpoint |
| **Import PRT** | Paste a raw PRT you got elsewhere (from `ROADtools`, a compromised host, and so on) |
| **PRT → Access Token** | Turns the PRT into an access token for a given resource, using HMAC-SHA256 signed JWTs |
| **PRT → SSO Cookie** | Turns the PRT into an `x-ms-RefreshTokenCredential` browser cookie for SSO sessions |
| **Register WinHello Key** | Registers a Windows Hello for Business NGC key bound to the device cert |

## Token exchange

Trades a captured refresh token for an access token aimed at a different resource. Useful for pivoting off a Graph token into other Microsoft services.

| Field | Notes |
|-------|-------|
| **Protocol** | `v1.0` (uses the `resource` parameter) or `v2.0` (uses the `scope` parameter) |
| **Resource / Scope** | The target resource URI or scope string |
| **Client ID** | Override the client ID used in the exchange, if you need to |
| **Tenant lookup** | Resolve a domain to its Entra tenant ID |

Common resources for a v1.0 exchange:

| Service | Resource URI |
|---------|-------------|
| Microsoft Graph | `https://graph.microsoft.com` |
| SharePoint | `https://<tenant>.sharepoint.com` |
| Azure Management | `https://management.azure.com` |
| Key Vault | `https://vault.azure.net` |
| My Sign-ins (MFA) | `19db86c3-b2b9-44cc-b339-36da233a3be2` |

## Persistence modules

The **Graph Actions** page holds the tenant-mutating operations. Every one is logged in the [deployment ledger](#deployment-ledger-and-teardown) with a rollback descriptor, so nothing you push into the client tenant gets forgotten.

| Module | What it does | Rollback |
|--------|--------------|----------|
| **CA Exclusion Policy** | Creates a Conditional Access policy that forces a control (MFA) on everyone except the operator. Starts in `enabledForReportingButNotEnforced` (report-only); you opt into `enabled`. | `DELETE /identity/conditionalAccess/policies/{id}` (auto) |
| **SP Backdoor — Add Client Secret** | Adds a password credential to an application (`addPassword`). The secret is shown once and never stored in the ledger; only the `keyId` is kept for revocation. | `POST /applications/{id}/removePassword` (auto) |
| **SP Backdoor — Add Certificate** | Adds a self-signed certificate credential (Regla #3: a cert outlives a secret and makes less noise). Builds the keypair locally and returns the private key once, for client_credentials auth. Meant for a dedicated backdoor app you created. | `PATCH /applications/{id}` clearing `keyCredentials` (auto) |
| **Assign App Role** | Grants an app role to a principal SP on a resource SP, for example `RoleManagement.ReadWrite.Directory` on the Graph SP. Comes with a **Find Graph SP** helper. | `DELETE /servicePrincipals/{resource}/appRoleAssignedTo/{id}` (auto) |
| **Assign Directory Role** | Assigns a directory role (Global Administrator by default) to a principal at a scope. | `DELETE /roleManagement/directory/roleAssignments/{id}` (auto) |

These are GA / Security-Admin-level techniques. They need a captured token that already holds the matching directory privilege, and they don't escalate privilege on their own.

## Deployment ledger and teardown

Every mutation Entraith pushes into a target tenant, the persistence modules above plus app and group deploys, injected MFA methods, registered devices, and Windows Hello keys, is recorded in the `deployed_artifacts` ledger. Open **🧹 Deployment Ledger** in the Advanced Tools sidebar to review and revert.

| | |
|---|---|
| **What is recorded** | Type, created object id, the exact call that created it, operator, campaign/target, the audit signature it triggers, a secret-by-reference pointer, and a rollback descriptor. |
| **Auto rollback** | Graph-kind artifacts (app registration, group clone, CA policy, SP credential, app-role and directory-role assignment) revert in one click using the campaign's token. |
| **Manual rollback** | Device registration (DRS), Windows Hello keys, and injected MFA methods are session- or DRS-bound. They're surfaced with explicit instructions instead of being run for you. |
| **Teardown order** | `POST /api/campaigns/{id}/teardown` walks the ledger newest-first (dependants before parents), reverts every auto-revertible artifact, and returns a per-artifact result set. |

The ledger doubles as an engagement evidence trail and a purple-team detection map: each row names the Entra audit event it generates.
