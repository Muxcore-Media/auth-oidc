# Auth OIDC

OIDC authentication and authorization for MuxCore.

This module implements the same three capabilities as `auth-local`, but delegates
sign-in to an external IdP (Authentik, Keycloak, Dex, etc.):

| Contract | Capability | Purpose |
|----------|-----------|---------|
| `AuthProvider` | `"auth"` | Opaque session tokens; Validate / Revoke |
| `Authorizer` | `"authorizer"` | RBAC via `policies.yaml` |
| `IdentityProvider` | `"identity"` | Extract caller identity from bearer token |

Browser login matches **auth-local’s HTTP contract** so `admin-ui` can point
`ADMIN_UI_AUTH_ADDR` at this module with no callback rewrite.

## Login flow

```
admin-ui                  auth-oidc                 IdP
   |  GET /login?redirect=     |                      |
   |-------------------------->|                      |
   |                           |  redirect to /authorize
   |                           |--------------------->|
   |                           |  GET /oidc/callback?code=
   |                           |<---------------------|
   |  303 redirect?code=       |  (session created)   |
   |<--------------------------|                      |
   |  POST /login/exchange     |                      |
   |-------------------------->|                      |
   |  {token,user_id,...}      |                      |
   |<--------------------------|                      |
```

One-time exchange codes expire in **30 seconds** (same as auth-local).
Session bearer tokens are opaque SHA-256 hex strings (24h TTL by default).

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_OIDC_ISSUER` | — | OIDC issuer URL (required) |
| `AUTH_OIDC_CLIENT_ID` / `CLIENT_ID` | — | Confidential client ID |
| `AUTH_OIDC_CLIENT_SECRET` / `CLIENT_SECRET` | — | Client secret |
| `AUTH_OIDC_REDIRECT_URL` / `REDIRECT_URL` | — | Must be `http(s)://<module-http>/oidc/callback` |
| `AUTH_OIDC_GRPC_ADDR` | `:9410` | gRPC listen (AuthService) |
| `AUTH_OIDC_HTTP_ADDR` | `:9411` | HTTP listen (login / callback / exchange) |
| `AUTH_OIDC_POLICY_FILE` | `policies.yaml` | RBAC policy |
| `AUTH_OIDC_ROLES_CLAIM` / `ROLES_CLAIM` | `groups` | Claim holding roles/groups |
| `AUTH_OIDC_ROLE_MAP` | — | Optional `IdPRole=localRole,...` map |
| `AUTH_OIDC_DEFAULT_ROLES` | `user` | Roles when claim empty / unmapped |

Short names `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URL`, and `ROLES_CLAIM` are
accepted as fallbacks for the `AUTH_OIDC_*` vars.

### New dependencies

- `github.com/coreos/go-oidc/v3` — discovery, ID token verify
- `golang.org/x/oauth2` — auth-code exchange

## Authentik example

1. Create an OAuth2/OIDC provider application with redirect URI
   `http://localhost:9411/oidc/callback`.
2. Note the **OpenID Configuration Issuer** URL (often ends with
   `/application/o/<slug>/`).
3. Create a confidential client; copy client ID and secret.
4. Map groups into the `groups` claim (or set `AUTH_OIDC_ROLES_CLAIM`).

```bash
export AUTH_OIDC_ISSUER=https://authentik.example.com/application/o/muxcore/
export AUTH_OIDC_CLIENT_ID=muxcore
export AUTH_OIDC_CLIENT_SECRET=...
export AUTH_OIDC_REDIRECT_URL=http://localhost:9411/oidc/callback
export AUTH_OIDC_ROLE_MAP=muxcore-admins=admin,muxcore-users=user
export MUXCORE_INSECURE_DISABLE_TLS=true

make build
./auth-oidc
```

Point admin-ui at the module HTTP port:

```bash
export ADMIN_UI_AUTH_ADDR=http://localhost:9411
```

## Keycloak example

1. Create a client (`muxcore`) with **Standard flow** enabled and
   Valid redirect URI `http://localhost:9411/oidc/callback`.
2. Issuer is typically `https://keycloak.example.com/realms/<realm>`.
3. Client authentication: On (confidential); copy secret from Credentials.
4. Map realm roles or groups into a claim (default `groups`), or set
   `AUTH_OIDC_ROLES_CLAIM=realm_access.roles` only if your IdP flattens that
   claim — otherwise prefer a protocol mapper that emits a top-level string
   array and map with `AUTH_OIDC_ROLE_MAP`.

```bash
export AUTH_OIDC_ISSUER=https://keycloak.example.com/realms/muxcore
export AUTH_OIDC_CLIENT_ID=muxcore
export AUTH_OIDC_CLIENT_SECRET=...
export AUTH_OIDC_REDIRECT_URL=http://localhost:9411/oidc/callback
export AUTH_OIDC_ROLE_MAP=admin=admin,user=user
```

## gRPC AuthService

Implemented: `Validate`, `Revoke`, `ExtractIdentity`, `Can`.

`Authenticate` returns an error payload directing clients to the HTTP OIDC flow.
User CRUD, TOTP, WebAuthn, and API tokens return `Unimplemented` — manage users
in the IdP (or keep `auth-local` for local admin user mgmt when not using SSO).

## Build & test

```bash
cd auth-oidc
make build
make test
```

Unit tests use a fake IdP (`oidc.Fake`) and `httptest` — no live issuer required.
