# OIDC/SSO Auth Provider

OpenID Connect and OAuth2 authentication provider for MuxCore. Supports Google, GitHub, Authelia, Authentik, Keycloak, and any OIDC-compliant identity provider.

Implements `contracts.AuthProvider`.

## Configuration

- `MUXCORE_AUTH_OIDC_ISSUER` — OIDC issuer URL
- `MUXCORE_AUTH_OIDC_CLIENT_ID` — OAuth2 client ID
- `MUXCORE_AUTH_OIDC_CLIENT_SECRET` — OAuth2 client secret
- `MUXCORE_AUTH_OIDC_REDIRECT_URL` — Callback URL
- `MUXCORE_AUTH_OIDC_SCOPES` — Additional scopes (default: openid profile email)
- `MUXCORE_AUTH_OIDC_ALLOWED_DOMAINS` — Restrict to email domains (optional)

## License

GPL-3.0
