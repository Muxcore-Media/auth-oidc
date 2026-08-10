# Compatibility

## Core Version

| Module Version | Core Version | Status |
|----------------|-------------|--------|
| v0.1.2           | 0.5.0+     | Current |
| v0.1.1           | 0.5.0+     | Superseded |
| v0.1.0           | 0.4.0+     | Superseded |

MVP host stacks pin **core@v0.5.0**. This module declares `minCoreVersion` **0.4.0**.

## Capabilities

- `auth`
- `authorizer`
- `identity`
- `settings`

## Soft-fail / optional

`auth-oidc` is **optional**. Spool `minimal`/`media` and the installer default to
`auth-local`. With IdP env unset, the process still starts; login/callback return
HTTP 503 and Health reports soft-disabled until issuer/client/redirect are set.

## Contracts

Implements AuthProvider / Authorizer / IdentityProvider contracts from core (same surface as auth-local).

## Breaking Changes

Pre-1.0 module: interfaces may change without a major version bump. Prefer published tags over `main`/`master` HEAD in production.

## Intentional gaps vs auth-local

User CRUD, TOTP, WebAuthn, and API-token AuthService RPCs return gRPC `Unimplemented`.
Manage those in the IdP. See README “gRPC AuthService — intentional Unimplemented RPCs”.
