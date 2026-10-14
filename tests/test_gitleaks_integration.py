"""Real scanner checks run when Gitleaks is installed (for example in Docker)."""
import shutil
from pathlib import Path

import pytest

from secretshield.scanner import run_gitleaks


GITLEAKS = shutil.which("gitleaks")
pytestmark = pytest.mark.skipif(not GITLEAKS, reason="Gitleaks binary is unavailable on this test host")
ROOT = Path(__file__).parents[1]
CONFIG = ROOT / ".gitleaks.toml"


def test_gitleaks_detects_exact_aws_sample_but_keeps_example_id_allowlist(tmp_path):
    (tmp_path / "secret_test.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'AWS_SECRET_ACCESS_KEY = "fakeSecretValueForTesting123456"\n'
    )
    report = run_gitleaks(tmp_path, GITLEAKS, timeout=20, config_path=CONFIG)
    assert any(finding["RuleID"] == "aws-secret-access-key-assignment"
               and finding["File"].endswith("secret_test.py") and finding["StartLine"] == 2
               for finding in report)
    assert not any(finding["RuleID"] == "aws-access-token" for finding in report)


def test_gitleaks_detects_generic_supported_pattern_and_scans_clean_source(tmp_path):
    source = tmp_path / "generic.py"
    # Avoid obvious sequences/placeholder stop words so this exercises the
    # generic detector rather than Gitleaks' intentional false-positive filter.
    fixture_value = "G7mQ2vN9cR4xL8pK5wT3zH6jD1fB0yUa"
    source.write_text(f'API_KEY = "{fixture_value}"\n')
    report = run_gitleaks(tmp_path, GITLEAKS, timeout=20, config_path=CONFIG)
    assert report, "expected generic supported credential-shaped value to be reported"
    assert any(finding["RuleID"] == "generic-api-key" for finding in report)
    source.write_text('print("hello world")\n')
    report = run_gitleaks(tmp_path, GITLEAKS, timeout=20, config_path=CONFIG)
    assert report == []


def test_gitleaks_intentionally_suppresses_generic_placeholder_values(tmp_path):
    (tmp_path / "placeholder.py").write_text('API_KEY = "fakeSecretValueForTesting123456"\n')
    report = run_gitleaks(tmp_path, GITLEAKS, timeout=20, config_path=CONFIG)
    assert not any(finding["RuleID"] == "generic-api-key" for finding in report)
