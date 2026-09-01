# Auth OIDC

OIDC authentication and authorization for MuxCore.

**Optional module.** The installer and demo stacks default to **`auth-local`**
(password bootstrap, no external IdP). Use `auth-oidc` only when you want SSO
against a self-hosted IdP (Keycloak, Authentik, Dex, …). Do not enable both in
the same mesh.

When `AUTH_OIDC_ISSUER` / client / redirect are unset, the process **starts** but
stays **soft-disabled**: `Health` and `GET /health` report unhealthy, and login
returns HTTP 503 until IdP settings are provided (via env or SettingsProvider).

This module implements the same three capabilities as `auth-local`, but delegates
sign-in to an external IdP:

| Contract | Capability | Purpose |
|----------|-----------|---------|
| `AuthProvider` | `"auth"` | Opaque session tokens; Validate / Revoke |
| `Authorizer` | `"authorizer"` | RBAC via `policies.yaml` |
| `IdentityProvider` | `"identity"` | Extract caller identity from bearer token |

Browser login matches **auth-local’s HTTP contract** so `admin-ui` can point
`ADMIN_UI_AUTH_ADDR` at this module with no callback rewrite.

## Installer default

[`muxcore-installer`](https://github.com/Muxcore-Media/muxcore-installer) wires
**`auth-local`** (`ESSENTIAL` / `up.sh`). `auth-oidc` is not part of the default
install; add it only after you have a local IdP and replace (do not dual-run)
`auth-local` in the spool/tag.

## Login flow

```
admin-ui                  auth-oidc                 IdP
   |  GET /login?redirect=     |                      |
   |-------------------------->|                      |
   |                           |  redirect to /authorize (PKCE+nonce)
   |                           |--------------------->|
   |                           |  GET /oidc/callback?code=
   |                           |<---------------------|
   |  303 redirect?code=       |  (session created)   |
   |<--------------------------|                      |
   |  POST /login/exchange     |                      |
   |-------------------------->|                      |
   |  {token,user_id,...}      |                      |
   |<--------------------------|                      |
   |  GET /logout (optional)   |                      |
   |-------------------------->|  revoke session      |
   |                           |  redirect end_session|
   |                           |--------------------->|
   |  /login (SSO again)       |                      |
   |<--------------------------|                      |
```

Admin-ui and media-ui clear their local cookie on `/logout`, then redirect through
auth-oidc `GET /logout?token=…&redirect=…` when wired for RP-initiated IdP logout.

One-time exchange codes expire in **30 seconds** (same as auth-local).
Session bearer tokens are opaque SHA-256 hex strings (24h TTL by default, override
with `AUTH_OIDC_SESSION_TTL`).

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_OIDC_ISSUER` | — | OIDC issuer URL (required for live SSO; unset → soft-disabled) |
| `AUTH_OIDC_CLIENT_ID` / `CLIENT_ID` | — | Confidential client ID |
| `AUTH_OIDC_CLIENT_SECRET` / `CLIENT_SECRET` | — | Client secret |
| `AUTH_OIDC_REDIRECT_URL` / `REDIRECT_URL` | — | Must be `http(s)://<module-http>/oidc/callback` (public: `https://auth.zem.systems/oidc/callback`) |
| `AUTH_OIDC_SCOPES` | `openid profile email` | Extra scopes (e.g. `groups`) |
| `AUTH_OIDC_GRPC_ADDR` | `:9410` | gRPC listen (AuthService) |
| `AUTH_OIDC_HTTP_ADDR` | `:9412` | HTTP listen (login / callback / exchange) |
| `AUTH_OIDC_DB_PATH` | `~/.muxcore/auth-oidc.db` | SQLite session store |
| `AUTH_OIDC_POLICY_FILE` | `policies.yaml` | RBAC policy |
| `AUTH_OIDC_ROLES_CLAIM` / `ROLES_CLAIM` | `groups` | Claim holding roles/groups (supports dotted paths and `resource_access.*.roles`) |
| `AUTH_OIDC_ROLE_MAP` | — | Optional `IdPRole=localRole,...` map |
| `AUTH_OIDC_DEFAULT_ROLES` | `user` | Roles when claim empty / unmapped |
| `AUTH_ALLOWED_REDIRECT_HOSTS` | — | Comma-separated hosts/URLs allowed in `?redirect=` after login |
| `AUTH_OIDC_SESSION_TTL` | `24h` | MuxCore opaque session lifetime |
| `ADMIN_UI_PUBLIC_URL` / `MEDIA_UI_PUBLIC_URL` | — | Also allowlisted for post-login redirect (host env on vault) |

Short names `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URL`, and `ROLES_CLAIM` are
accepted as fallbacks for the `AUTH_OIDC_*` vars.

### MVP stack note

`_mvp/run-host.sh` can start **both** `auth-local` and `auth-oidc` when
`MVP_ENABLE_AUTH_OIDC=1`, but the mesh expects **one** `AuthProvider`. Use OIDC as
a swap-in replacement for `auth-local`, not alongside it.

### Soft-fail (IdP unset)

| Surface | Behavior |
|---------|----------|
| `Init` / `Start` | Succeed (module stays up) |
| `Health` | Error: soft-disabled or IdP unreachable |
| `GET /health` | `503` when unhealthy |
| `GET /login`, `/oidc/callback` | `503` OIDC IdP not configured |

### New dependencies

- `github.com/coreos/go-oidc/v3` — discovery, ID token verify
- `golang.org/x/oauth2` — auth-code exchange

## Local Keycloak (Docker Compose)

No cloud IdP required. When Docker is available:

```bash
./deploy/run-keycloak-test.sh
# or:
KEYCLOAK_HOST_PORT=18080 docker compose -f deploy/docker-compose.yml up -d --wait
go test -count=1 -timeout 5m ./internal/oidc/ -run TestKeycloakComposeDiscovery
```

Compose starts Keycloak with realm `muxcore`, client `muxcore` /
secret `muxcore-test-secret`, user `alice` / `alice`. Discovery:

```text
http://127.0.0.1:18080/realms/muxcore/.well-known/openid-configuration
```

If Docker is unavailable, unit tests still cover soft-fail and Fake IdP login;
skip the compose path and use the files under `deploy/` when Docker is present.
Authentik works the same way as Keycloak once you set issuer/client/redirect
(see below) — Keycloak is the checked-in compose fixture.

## Authentik example

1. Create an OAuth2/OIDC provider application with redirect URI
   `http://localhost:9412/oidc/callback`.
2. Note the **OpenID Configuration Issuer** URL (often ends with
   `/application/o/<slug>/`).
3. Create a confidential client; copy client ID and secret.
4. Map groups into the `groups` claim (or set `AUTH_OIDC_ROLES_CLAIM`).

```bash
export AUTH_OIDC_ISSUER=https://authentik.example.com/application/o/muxcore/
export AUTH_OIDC_CLIENT_ID=muxcore
export AUTH_OIDC_CLIENT_SECRET=...
export AUTH_OIDC_REDIRECT_URL=http://localhost:9412/oidc/callback
export AUTH_OIDC_ROLE_MAP=muxcore-admins=admin,muxcore-users=user
export MUXCORE_INSECURE_DISABLE_TLS=true

make build
./auth-oidc
```

Point admin-ui at the module HTTP port:

```bash
export ADMIN_UI_AUTH_ADDR=http://localhost:9412
```

## Keycloak example

1. Create a client (`muxcore`) with **Standard flow** enabled and
   Valid redirect URI `http://localhost:9412/oidc/callback`.
2. Issuer is typically `https://keycloak.example.com/realms/<realm>`
   (or the compose URL above for laptop).
3. Client authentication: On (confidential); copy secret from Credentials.
4. Map realm roles or groups into a claim (default `groups`), or set
   `AUTH_OIDC_ROLES_CLAIM=realm_access.roles` only if your IdP flattens that
   claim — otherwise prefer a protocol mapper that emits a top-level string
   array and map with `AUTH_OIDC_ROLE_MAP`.

```bash
export AUTH_OIDC_ISSUER=https://keycloak.example.com/realms/muxcore
export AUTH_OIDC_CLIENT_ID=muxcore
export AUTH_OIDC_CLIENT_SECRET=...
export AUTH_OIDC_REDIRECT_URL=http://localhost:9412/oidc/callback
export AUTH_OIDC_ROLE_MAP=admin=admin,user=user
```

## Parity with auth-local

| Area | auth-local | auth-oidc |
|------|------------|-----------|
| Installer / demo default | **Yes** | Optional SSO swap-in |
| Capabilities | `auth`, `authorizer`, `identity` | Same |
| Browser login HTTP | `/login`, `/login/exchange` | Same contract; IdP redirect via `/oidc/callback` |
| Session tokens | Opaque SHA-256 hex | Same shape / Validate / Revoke |
| RBAC | `policies.yaml` (+ SIGHUP) | Same (`AUTH_OIDC_POLICY_FILE`) |
| Password / TOTP / WebAuthn login | Local store | **IdP only** (not in this module) |
| User CRUD / API tokens gRPC | Implemented | **Unimplemented** (IdP owns users) |
| Drop-in for admin-ui | `ADMIN_UI_AUTH_ADDR` | Same — point at `:9412` HTTP |

Use **one** auth module per mesh. Prefer `auth-local` for installer/laptop demos;
switch to `auth-oidc` for SSO against a self-hosted IdP.

## gRPC AuthService — intentional Unimplemented RPCs

**Implemented:** `Validate`, `Revoke`, `ExtractIdentity`, `Can`.

`Authenticate` returns an error directing clients to the HTTP OIDC flow (no password path here).

| RPC family | Methods | Behavior |
|------------|---------|----------|
| User CRUD | `CreateUser`, `DeleteUser`, `ListUsers`, `SetPassword`, `SetRoles` | `Unimplemented` — manage users/roles in the IdP |
| TOTP | `EnableTOTP`, `DisableTOTP`, `TOTPStatus`, `VerifyTOTPSetup` | `Unimplemented` — MFA in the IdP |
| WebAuthn | `ListWebAuthnCredentials`, `DeleteWebAuthnCredential`, `BeginAdminRegistration`, `CompleteAdminRegistration` | `Unimplemented` — passkeys in the IdP |
| API tokens | `CreateAPIToken`, `ListAPITokens`, `DeleteAPIToken` | `Unimplemented` — not supported in auth-oidc |

Covered by `TestUnimplementedUserCRUD` in `internal/server`.

## Build & test

```bash
cd auth-oidc
make build
make test
```

Unit tests use a fake IdP (`oidc.Fake`) and `httptest` — no live issuer required.
`TestModuleSoftFailWhenIdPUnset` proves start + unhealthy soft-disable without IdP.
`TestKeycloakComposeDiscovery` runs against local Keycloak when Docker is up
(skips otherwise).
