import json
import sys

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def severity(rule):
    name = rule.lower()
    if any(item in name for item in ("private-key", "private_key", "aws-access-token", "aws-secret-key", "aws-secret-access-key", "github-pat", "gcp-service-account")):
        return "critical"
    if any(item in name for item in ("aws", "token", "password", "secret", "api-key", "apikey", "slack", "stripe", "database")):
        return "high"
    if any(item in name for item in ("generic", "jwt", "oauth", "credential")):
        return "medium"
    return "low"


def main():
    threshold = sys.argv[1] if len(sys.argv) > 1 else "high"
    if threshold not in RANK:
        print("Invalid BLOCK_AT_SEVERITY policy; choose critical, high, medium, or low.", file=sys.stderr)
        return 2
    try:
        findings = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        print("Secret scan failed: scanner report was invalid.", file=sys.stderr)
        return 2
    counts = {name: 0 for name in RANK}
    for finding in findings:
        counts[severity(str(finding.get("RuleID", "unknown")))] += 1
    print("Secret scan summary: " + ", ".join(f"{name}={count}" for name, count in counts.items()))
    blocked = sum(value for name, value in counts.items() if RANK[name] >= RANK[threshold])
    print(f"Policy: block at {threshold} or above; blocked findings={blocked}")
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
