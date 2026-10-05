# Changelog

## [Unreleased]

### Security
- OIDC discovery, token exchange, and the end-session endpoint go through netguard Integration (private LAN and loopback allowed for a household IdP; link-local, cloud metadata, and non-HTTP schemes refused). A blocked issuer is rejected before it is stored (NFR-SEC-009).

## [0.1.9] - 2026-10-05


### Security
- gRPC server and peer dials use mesh TLS (meshtls, sdk/go/module v0.6.5) unless the dev insecure flag is set (ADR-0016/0017).

## [0.1.8] - 2026-10-05

### Changed
- Built on core v0.6.14 / sdk/go/module v0.6.4: unregisters on shutdown and re-registers after core restarts (ADR-0022).

## [0.1.7] - 2026-10-05


### Changed
- Reported version comes from muxcore.json (ADR-0021); built on core v0.6.12 / sdk/go/module v0.6.3 (mesh enrollment, ADR-0017).

## [0.1.6] - 2026-10-05


### Security
- `ExtractIdentity` no longer grants a `service` identity from a client-supplied `CallerId`; it is honoured only when the TLS peer certificate chain is verified and its CN equals the `CallerId` (same rule as auth-local; ADR-0017, NFR-SEC-002). Token-only (user) flows unchanged. `Can` only resolves user sessions and grants nothing to bare module IDs.

## [0.1.3] - 2026-10-05

### Changed
- CI runs on GitHub-hosted runners from the umbrella template; retired-origin workflows removed.
- Dependencies resolve from published GitHub tags (no filesystem `replace`); requires core v0.6.0.

### Added

- Soft-fail when IdP unset: module starts; `Health` / `GET /health` report soft-disabled; login returns 503
- Local Keycloak Docker Compose fixture (`deploy/`) + `deploy/run-keycloak-test.sh` (skips without Docker)
- README: optional module; installer default remains `auth-local`

## [0.1.2] — 2026-08-10

### Added

- SettingsProvider for OIDC knobs (`issuer`, `client_id`, `client_secret`, `redirect_url`, roles mapping) and `policy_file`
- Live OIDC provider rebuild via `webapp.Handler.SetFlow`; policy reload on `policy_file` updates
- Advertises `settings` capability for admin-ui discovery

## [0.1.1] — 2026-08-09

### Added

- README parity table vs auth-local and intentional Unimplemented RPC matrix.
- SECURITY.md for SSO/session posture.

## [0.1.0] — 2026-08-09

### Added

- OIDC SSO via external IdP (Authentik, Keycloak, Dex, …)
- HTTP login contract compatible with admin-ui / media-ui
- RBAC via `policies.yaml`; user CRUD/TOTP/WebAuthn/API-token RPCs intentionally Unimplemented
