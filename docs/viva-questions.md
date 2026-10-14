# Viva questions and short answers

**What problem does SecretShield solve?** It detects code patterns that resemble credentials and helps prevent them from being merged through a CI gate.

**Does a match prove a key is live?** No. It is a candidate exposure that needs safe human review.

**Why use Gitleaks?** It is a dedicated open-source scanner for secrets in files and Git history; this project wraps it with authenticated workflow, safe upload handling, redaction, persistence, and policy.

**Why scan Git history?** Removing a secret from the latest file may leave old commits containing it.

**Why are raw values not stored?** The app needs a finding location and rule for remediation, not the secret itself. Persisting it would create another exposure.

**What is a keyed fingerprint?** An HMAC digest over scanner correlation metadata. It lets the app compare findings without persisting the raw value; it is not reversible and is not proof of a valid credential.

**How does the CI gate work?** It scans the repository history, classifies counts by an explicit severity policy, and returns a non-zero status if a finding meets the configured threshold.

**How does SecretShield prove remediation?** A finding is only marked resolved after a later successful scan of the same source has no matching keyed fingerprint. Acknowledgement by itself is not remediation evidence.

**What does incident management add?** It gives a finding an owner-facing response path, guarded status changes, remediation notes, a timeline, and an audit record.

**What happens after a real credential leak?** Revoke/rotate it with the provider, investigate its use, remove it from files and history as appropriate, replace it with a secret manager reference, and rescan.

**Why no AWS credentials in the app?** Credential values should not be entered into a dashboard. A future integration should use an instance role/provider chain with read-only IAM permissions.
