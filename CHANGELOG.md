# Changelog

## [0.1.2] — 2026-08-10

### Added

- SettingsProvider for OIDC knobs (`issuer`, `client_id`, `client_secret`, `redirect_url`, roles mapping) and `policy_file`
- Live OIDC provider rebuild via `webapp.Handler.SetFlow`; policy reload on `policy_file` updates
- Advertises `settings` capability for admin-ui discovery

## [Unreleased]

## [0.1.1] — 2026-08-09

### Added

- README parity table vs auth-local and intentional Unimplemented RPC matrix.
- SECURITY.md for SSO/session posture.

## [0.1.0] — 2026-08-09

### Added

- OIDC SSO via external IdP (Authentik, Keycloak, Dex, …)
- HTTP login contract compatible with admin-ui / media-ui
- RBAC via `policies.yaml`; user CRUD/TOTP/WebAuthn/API-token RPCs intentionally Unimplemented
