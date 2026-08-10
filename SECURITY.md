# Security Policy

## Reporting a Vulnerability

Report security vulnerabilities to the MuxCore team via security@muxcore.io or a
draft GitHub security advisory. Do not open public issues for security bugs.

## Scope

This module handles OIDC SSO session issuance, token validation, and RBAC against
IdP claims. Issues in the external IdP (Authentik, Keycloak, …) should be reported
to that vendor.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest tagged | ✅ |

## Security Posture

### Key properties

- Session tokens are opaque SHA-256(random) hex; never log full tokens
- Client secret and IdP tokens must come from env / secrets module — not committed config
- `AUTH_OIDC_REDIRECT_URL` must match the IdP allow-list exactly (open-redirect risk if mis-set)
- RBAC is local `policies.yaml`; roles still originate from IdP claims (+ optional `AUTH_OIDC_ROLE_MAP`)
- User passwords, TOTP, and WebAuthn are **not** stored here — intentional Unimplemented RPCs

### Threat notes

- Compromised `CLIENT_SECRET` allows impersonating the OIDC client — rotate via IdP
- Run TLS to core in production (`MUXCORE_INSECURE_DISABLE_TLS` is for local mesh only)
