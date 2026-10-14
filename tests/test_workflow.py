import json
import subprocess
import sys
from pathlib import Path
from secretshield.gate import evaluate_gate


def test_gate_passes_clean_and_blocks_high_findings():
    assert evaluate_gate([])["blocked"] is False
    result = evaluate_gate([{"RuleID": "aws-secret-key"}, {"RuleID": "generic-api-key"}], "high")
    assert result["blocked"] is True
    assert result["counts"]["critical"] == 1
    assert result["counts"]["high"] == 1


def test_gate_threshold_can_be_changed():
    findings = [{"RuleID": "generic-credential"}]
    assert evaluate_gate(findings, "high")["blocked"] is False
    assert evaluate_gate(findings, "medium")["blocked"] is True


def test_ci_gate_prints_counts_without_values():
    script = Path(__file__).parents[1] / ".github" / "scripts" / "evaluate_gate.py"
    raw_value = "fabricated-test-value-that-must-not-appear"
    report = json.dumps([{"RuleID": "aws-secret-key", "Secret": raw_value, "Match": raw_value}])
    result = subprocess.run([sys.executable, str(script), "high"], input=report, text=True, capture_output=True, check=False)
    assert result.returncode == 1
    assert "critical=1" in result.stdout
    assert raw_value not in result.stdout + result.stderr
