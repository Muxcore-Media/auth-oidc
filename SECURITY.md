# Security Policy

## Reporting a Vulnerability

**Do not open a public issue.** Disclose security vulnerabilities privately via
GitHub's built-in vulnerability reporting:

1. Go to the [Security Advisories](https://github.com/Muxcore-Media/auth-oidc/security/advisories) tab
2. Click **New draft security advisory**
3. Fill in the affected versions, severity, and a clear description with reproduction steps

You will receive an acknowledgement within **72 hours**. After triage, we will
keep you informed of progress and coordinate a disclosure timeline.

### What to Include

- Affected component and version
- Steps to reproduce, ideally as a minimal Go test case or `curl` one-liner
- Impact (data exposure, privilege escalation, denial of service, remote code execution)
- Whether you plan to disclose publicly and your preferred timeline

## Scope

### In Scope

- **Module logic** — bugs that affect the module's security boundary
- **API surface** — authentication bypass, authorization flaws, injection
- **Data handling** — leaks, unsafe serialization, missing validation
- **External integrations** — unsafe handling of third-party inputs or credentials
- **Configuration defaults** — insecure-by-default settings

### Out of Scope

- Issues in MuxCore core fabric (report those to the [core repo](https://github.com/Muxcore-Media/core/security/advisories))
- Issues in other MuxCore modules (report to the respective module repo)
- Infrastructure not controlled by MuxCore (user's reverse proxy, firewall, host OS)
- DoS via resource exhaustion on unauthenticated endpoints
- Social engineering, phishing, or physical attacks
- Vulnerabilities in dependencies with no upstream patch available

## Disclosure Policy

1. Reporter submits a private report via GitHub Security Advisories
2. Maintainers triage within 72 hours and assign a severity
3. A fix is developed in a private fork; the reporter is credited (with permission) in the advisory
4. A GitHub Security Advisory is published in coordination with the fix release

We follow **coordinated disclosure**. Please give a reasonable window (30 days by default)
to patch before going public.

## Security Model

MuxCore's security boundary is **between modules, not inside them**. Core provides
the fabric — event bus, registry, lifecycle — and each module runs with the
capabilities it declared. This module's attack surface:

- **Module → Core**: can this module escape its declared capabilities?
- **Module → Module**: can this module intercept or forge events bound for another?
- **Network → API**: can an unauthenticated caller reach a protected endpoint?

When reporting, frame issues against these boundaries. A bug in business logic
that stays within this module's own capabilities is a regular bug, not a
security vulnerability.

## Safe Harbor

We will not pursue legal action against security researchers who:

- Test against their own MuxCore instance or one they have explicit permission to test
- Avoid accessing or modifying data that does not belong to them
- Make a good-faith effort to avoid degradation of service during testing
- Follow this policy's reporting and disclosure process
