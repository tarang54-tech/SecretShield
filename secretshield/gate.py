from .scanner import severity_for

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate_gate(findings, block_at="high"):
    if block_at not in SEVERITY_RANK:
        raise ValueError("block_at must be critical, high, medium, or low")
    counts = {severity: 0 for severity in SEVERITY_RANK}
    for finding in findings:
        counts[severity_for(str(finding.get("RuleID", "unknown")))] += 1
    blocked = sum(count for severity, count in counts.items() if SEVERITY_RANK[severity] >= SEVERITY_RANK[block_at]) > 0
    return {"blocked": blocked, "threshold": block_at, "counts": counts}
