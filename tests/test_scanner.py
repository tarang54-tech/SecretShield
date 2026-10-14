import io
import json
import os
import stat
import zipfile
import re
import tomllib
from pathlib import Path
from unittest.mock import Mock
import pytest
from werkzeug.datastructures import FileStorage
from secretshield.scanner import ScanError, extract_zip, redact_report, run_gitleaks, scan_upload, severity_for


def test_redaction_discards_raw_match_and_secret():
    fabricated = "sspro_" + "A" * 32
    findings = redact_report([{"RuleID": "secretshield-demo-key", "Secret": fabricated,
                              "Match": "DEMO=" + fabricated, "File": "src/app.py", "StartLine": 8,
                              "Fingerprint": "abc:src/app.py:secretshield-demo-key:8"}], "/tmp/source", b"test-hmac-key")
    assert len(findings) == 1
    assert set(findings[0]) == {"fingerprint", "rule_id", "severity", "file_path", "line_number"}
    assert fabricated not in repr(findings)
    assert findings[0]["severity"] == "high"


def test_severity_classification_is_explicit():
    assert severity_for("aws-secret-key") == "critical"
    assert severity_for("generic-api-key") == "high"
    assert severity_for("jwt-token") == "high"
    assert severity_for("unknown-rule") == "low"


def test_zip_path_traversal_is_rejected(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../outside.py", "safe")
    with pytest.raises(ScanError, match="archive_unsafe_path"):
        extract_zip(archive, tmp_path / "out")


def test_zip_symlink_is_rejected(tmp_path):
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link.py")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(info, "../../outside.py")
    with pytest.raises(ScanError, match="archive_symlink_rejected"):
        extract_zip(archive, tmp_path / "out")


def test_zip_file_count_and_extension_limits(tmp_path):
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("one.py", "x")
        z.writestr("two.py", "y")
    with pytest.raises(ScanError, match="archive_too_many_files"):
        extract_zip(archive, tmp_path / "out", max_files=1)
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("program.exe", "safe")
    with pytest.raises(ScanError, match="unsupported_file_type"):
        extract_zip(archive, tmp_path / "out")


def test_zip_uncompressed_size_cap(tmp_path):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("large.txt", "a" * 4096)
    with pytest.raises(ScanError, match="archive_uncompressed_size_limit|archive_suspicious_compression_ratio"):
        extract_zip(archive, tmp_path / "out", max_uncompressed=1024)


def test_scan_upload_rejects_unsupported_type(app):
    settings = {"MAX_SCAN_BYTES": 1000, "MAX_ARCHIVE_FILES": 10, "GITLEAKS_PATH": "gitleaks", "SCAN_TIMEOUT_SECONDS": 2, "SCAN_TEMP_DIR": str(Path(app.instance_path) / "test-tmp")}
    file = FileStorage(stream=io.BytesIO(b"safe"), filename="tool.exe")
    with pytest.raises(ScanError, match="unsupported_file_type"):
        scan_upload(file, settings, b"key")


def test_gitleaks_wrapper_uses_argument_list_suppresses_logs_and_parses_stdout(monkeypatch):
    called = {}
    def fake_run(args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs
        return Mock(returncode=0, stdout=b"[]")
    monkeypatch.setattr("secretshield.scanner.subprocess.run", fake_run)
    assert run_gitleaks("/tmp/source path", binary="gitleaks", timeout=9) == []
    assert isinstance(called["args"], list)
    assert "--timeout" not in called["args"]
    assert called["kwargs"]["timeout"] == 14
    assert called["kwargs"].get("shell", False) is False
    assert called["kwargs"]["stdout"] == __import__("subprocess").PIPE
    assert called["kwargs"]["stderr"] == __import__("subprocess").DEVNULL


def test_scan_upload_only_returns_redacted_gitleaks_metadata(app, monkeypatch):
    fabricated = "sspro_" + "B" * 32
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *a, **k: [{"RuleID": "secretshield-demo-key", "Secret": fabricated, "Match": "key=" + fabricated, "File": "sample.py", "StartLine": 3, "Fingerprint": "hash:sample.py:rule:3"}])
    upload = FileStorage(stream=io.BytesIO(b"sample content"), filename="sample.py")
    settings = {"MAX_SCAN_BYTES": 1000, "MAX_ARCHIVE_FILES": 10, "GITLEAKS_PATH": "gitleaks", "GITLEAKS_CONFIG": "", "SCAN_TIMEOUT_SECONDS": 2, "SCAN_TEMP_DIR": str(Path(app.instance_path) / "test-tmp")}
    _, findings = scan_upload(upload, settings, b"key")
    assert fabricated not in repr(findings)
    assert findings[0]["file_path"] == "sample.py"


def test_exact_aws_sample_is_passed_to_scanner_and_rule_matches(app, monkeypatch):
    source_text = ('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
                   'AWS_SECRET_ACCESS_KEY = "fakeSecretValueForTesting123456"\n')
    config = tomllib.loads(Path(__file__).parents[1].joinpath(".gitleaks.toml").read_text())
    rule = next(item for item in config["rules"] if item["id"] == "aws-secret-access-key-assignment")
    assert re.search(rule["regex"], source_text)
    observed = {}
    def fake_gitleaks(source, *args, **kwargs):
        path = Path(source) / "secret_test.py"
        observed["contents"] = path.read_text()
        observed["config"] = args[3] if len(args) > 3 else kwargs.get("config_path")
        return [{"RuleID": "aws-secret-access-key-assignment", "Secret": "fakeSecretValueForTesting123456",
                 "Match": source_text.splitlines()[1], "File": "secret_test.py", "StartLine": 2,
                 "Fingerprint": "secret_test.py:2:aws-secret-access-key-assignment"}]
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", fake_gitleaks)
    settings = {"MAX_SCAN_BYTES": 1000, "MAX_ARCHIVE_FILES": 10, "GITLEAKS_PATH": "gitleaks",
                "GITLEAKS_CONFIG": str(Path(__file__).parents[1] / ".gitleaks.toml"),
                "SCAN_TIMEOUT_SECONDS": 2, "SCAN_TEMP_DIR": str(Path(app.instance_path) / "test-tmp")}
    upload = FileStorage(stream=io.BytesIO(source_text.encode()), filename="secret_test.py")
    _, findings = scan_upload(upload, settings, b"key")
    assert observed["contents"] == source_text
    assert observed["config"] == settings["GITLEAKS_CONFIG"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "aws-secret-access-key-assignment"
    assert findings[0]["file_path"] == "secret_test.py"
    assert findings[0]["line_number"] == 2
    assert findings[0]["severity"] == "critical"
    assert "fakeSecretValueForTesting123456" not in repr(findings)


@pytest.mark.parametrize("report", [[{"RuleID": "x", "File": "x.py", "StartLine": "bad"}],
                                      [{"RuleID": "x", "File": "../outside.py", "StartLine": 1}],
                                      ["malformed"]])
def test_invalid_gitleaks_metadata_fails_instead_of_looking_clean(report):
    with pytest.raises(ScanError, match="invalid_scanner_report"):
        redact_report(report, "/tmp/source", b"key")


def test_git_history_requires_dot_git_directory(app):
    upload = FileStorage(stream=io.BytesIO(b"safe"), filename="sample.py")
    settings = {"MAX_SCAN_BYTES": 1000, "MAX_ARCHIVE_FILES": 10, "GITLEAKS_PATH": "gitleaks", "GITLEAKS_CONFIG": "", "SCAN_TIMEOUT_SECONDS": 2, "SCAN_TEMP_DIR": str(Path(app.instance_path) / "test-tmp")}
    with pytest.raises(ScanError, match="git_history_requires_git_directory"):
        scan_upload(upload, settings, b"key", include_git_history=True)


def test_gitleaks_timeout_and_missing_binary_are_sanitized(monkeypatch, tmp_path):
    monkeypatch.setattr("secretshield.scanner.subprocess.run", Mock(side_effect=__import__("subprocess").TimeoutExpired("gitleaks", 1)))
    with pytest.raises(ScanError, match="scan_timeout"):
        run_gitleaks(tmp_path)
    monkeypatch.setattr("secretshield.scanner.subprocess.run", Mock(side_effect=FileNotFoundError()))
    with pytest.raises(ScanError, match="gitleaks_unavailable"):
        run_gitleaks(tmp_path)


@pytest.mark.parametrize(("stdout", "returncode", "error"),
                         [(b"private fabricated output", 2, "scanner_failed"),
                          (b"not-json fabricated output", 0, "invalid_scanner_report")])
def test_gitleaks_nonzero_and_unparseable_results_are_failures(monkeypatch, tmp_path, stdout, returncode, error):
    monkeypatch.setattr("secretshield.scanner.subprocess.run", Mock(return_value=Mock(returncode=returncode, stdout=stdout)))
    with pytest.raises(ScanError, match=error):
        run_gitleaks(tmp_path)


def test_missing_config_is_not_silently_ignored(tmp_path):
    with pytest.raises(ScanError, match="invalid_scanner_config"):
        run_gitleaks(tmp_path, config_path=tmp_path / "missing.toml")
