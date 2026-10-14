# Security model

## Protected data

Source uploads may contain credentials. SecretShield treats uploads and scanner reports as sensitive. Gitleaks stdout is captured in process memory; Gitleaks stderr and normal output are discarded. Parser output intentionally permits only rule ID, keyed fingerprint, severity, relative path, line, status, and timestamp. CSV exports follow the same redacted model.

The HMAC fingerprint uses the application signing key and scanner-provided location/rule fingerprint. It is non-reversible, but changing `SECRET_KEY` changes future fingerprints. It is for correlation, not authentication.

## Controls implemented

- Scrypt password hashing, no default account/password, and interactive administrator creation.
- Login rate limit, strong session protection, HTTP-only SameSite cookies, CSRF protection, logout by POST, and session clearing at login.
- Security headers and restrictive same-origin Content Security Policy; no CORS is enabled.
- All scan/findings queries are scoped to the authenticated user. API authentication errors return 401.
- ORM parameterization; no shell-based scanner invocation.
- Bounded uploads, extension allowlist, ZIP traversal/symlink/file-count/size/ratio checks, per-scan timeout, and cleanup.
- Docker app runs non-root; Postgres is private; scanner has no Docker socket or AWS permissions.
- CSV export prefixes formula-like cells to reduce spreadsheet formula injection.

## Operational limitations

The login limiter uses in-memory storage in the single-process teaching setup. For multi-worker production deployments, configure a shared storage backend. The app lacks MFA/SSO, user provisioning, external audit shipping, distributed scan queue, and a production HTTPS reverse proxy. `COOKIE_SECURE=1` should be enabled behind HTTPS. Do not expose the dashboard publicly as configured.

Raw uploaded source is processed on the app host, so only scan code you are authorized to submit. A real exposed credential should be revoked/rotated with its provider; SecretShield does not perform that action.
