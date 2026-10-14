import io
from secretshield.models import Finding


def test_scan_persists_redacted_findings_only(logged_in, app, monkeypatch):
    raw_secret = "fabricated-only-sspro_" + "C" * 32
    report = [{"RuleID": "secretshield-demo-key", "Secret": raw_secret,
               "Match": "TOKEN=" + raw_secret, "File": "src/settings.py", "StartLine": 14,
               "Fingerprint": "fake-commit:src/settings.py:secretshield-demo-key:14"}]
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: report)
    response = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"demo source"), "source.py")}, content_type="multipart/form-data")
    assert response.status_code == 201
    assert raw_secret not in response.get_data(as_text=True)
    assert "Secret" not in response.get_data(as_text=True)
    findings = logged_in.get("/api/findings").get_json()["findings"]
    assert len(findings) == 1
    assert findings[0]["file_path"] == "src/settings.py"
    with app.app_context():
        persisted = Finding.query.one()
        assert raw_secret not in repr({column.name: getattr(persisted, column.name) for column in Finding.__table__.columns})


def test_exact_aws_sample_is_persisted_as_redacted_finding(logged_in, app, monkeypatch):
    raw_secret = "fakeSecretValueForTesting123456"
    source = b' AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\nAWS_SECRET_ACCESS_KEY = "fakeSecretValueForTesting123456"\n'
    report = [{"RuleID": "aws-secret-access-key-assignment", "Secret": raw_secret,
               "Match": source.decode().splitlines()[1], "File": "secret_test.py", "StartLine": 2,
               "Fingerprint": "secret_test.py:2:aws-secret-access-key-assignment"}]
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: report)
    response = logged_in.post("/api/scans", data={"file": (io.BytesIO(source), "secret_test.py")}, content_type="multipart/form-data")
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["scan"]["status"] == "completed"
    assert payload["scan"]["finding_count"] == 1
    assert payload["findings"][0]["rule_id"] == "aws-secret-access-key-assignment"
    assert payload["findings"][0]["file_path"] == "secret_test.py"
    assert payload["findings"][0]["line_number"] == 2
    assert payload["findings"][0]["severity"] == "critical"
    assert raw_secret not in response.get_data(as_text=True)
    with app.app_context():
        persisted = Finding.query.one()
        assert persisted.file_path == "secret_test.py"
        assert persisted.line_number == 2
        assert raw_secret not in repr({column.name: getattr(persisted, column.name) for column in Finding.__table__.columns})


def test_generic_supported_pattern_and_clean_scan_results(logged_in, monkeypatch):
    reports = [[{"RuleID": "generic-api-key", "Secret": "sspro_A1B2C3D4E5F6G7H8",
                 "File": "generic.py", "StartLine": 1, "Fingerprint": "generic.py:1:generic-api-key"}], []]
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: reports.pop(0))
    found = logged_in.post("/api/scans", data={"file": (io.BytesIO(b'API_TOKEN = "sspro_A1B2C3D4E5F6G7H8"'), "generic.py")}, content_type="multipart/form-data")
    assert found.status_code == 201
    assert found.get_json()["scan"]["finding_count"] == 1
    clean = logged_in.post("/api/scans", data={"file": (io.BytesIO(b'print("hello")'), "clean.py")}, content_type="multipart/form-data")
    assert clean.status_code == 201
    assert clean.get_json()["scan"]["status"] == "completed"
    assert clean.get_json()["scan"]["finding_count"] == 0


def test_malformed_scanner_report_is_failed_scan_not_clean(logged_in, monkeypatch):
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: [{"RuleID": "x", "File": "x.py", "StartLine": "bad"}])
    response = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"source"), "x.py")}, content_type="multipart/form-data")
    assert response.status_code == 422
    assert response.get_json()["scan"]["status"] == "failed"
    assert response.get_json()["scan"]["error_code"] == "invalid_scanner_report"


def test_scan_failure_is_safe_and_history_scope_is_enforced(logged_in, monkeypatch):
    response = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"not a zip"), "bad.zip"), "git_history": "true"}, content_type="multipart/form-data")
    assert response.status_code == 422
    assert response.get_json()["scan"]["error_code"] == "invalid_zip"


def test_repository_history_scan_is_recorded_as_distinct_source_type(logged_in, monkeypatch):
    import zipfile
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        bundle = Path(temp_dir) / "repo.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            info = zipfile.ZipInfo(".git/HEAD")
            info.create_system = 3
            info.external_attr = (0o100644 << 16)
            archive.writestr(info, "ref: refs/heads/main")
            archive.writestr("app.py", "print('safe')")
        monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: [])
        with bundle.open("rb") as handle:
            response = logged_in.post("/api/scans", data={"file": (handle, "repo.zip"), "git_history": "true"}, content_type="multipart/form-data")
    assert response.status_code == 201
    assert response.get_json()["scan"]["source_type"] == "git-history"


def test_finding_acknowledgement_is_not_resolution(logged_in, app, monkeypatch):
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: [{"RuleID": "generic-api-key", "Secret": "fake", "File": "x.py", "StartLine": 1, "Fingerprint": "fake:x:1"}])
    scan = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"demo"), "source.py")}, content_type="multipart/form-data").get_json()["scan"]
    finding = logged_in.get("/api/findings").get_json()["findings"][0]
    ack = logged_in.post(f"/api/findings/{finding['id']}/acknowledge")
    assert ack.status_code == 200
    assert ack.get_json()["finding"]["status"] == "acknowledged"
    assert logged_in.get(f"/scans/{scan['id']}").get_json()["findings"][0]["status"] == "acknowledged"


def test_csv_report_is_user_scoped_and_excludes_raw_secret(logged_in, monkeypatch):
    secret = "made-up-secret-value"
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: [{"RuleID": "generic-api-key", "Secret": secret, "File": "x.py", "StartLine": 1, "Fingerprint": "fp"}])
    logged_in.post("/api/scans", data={"file": (io.BytesIO(b"demo"), "source.py")}, content_type="multipart/form-data")
    response = logged_in.get("/api/reports/findings.csv")
    assert response.status_code == 200
    assert "text/csv" in response.content_type
    assert secret not in response.get_data(as_text=True)


def test_finding_only_resolves_after_clean_later_scan(logged_in, monkeypatch):
    finding_report = [{"RuleID": "generic-api-key", "Secret": "fake", "File": "src/app.py", "StartLine": 4, "Fingerprint": "stable-location-fingerprint"}]
    reports = [finding_report, finding_report, []]
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: reports.pop(0))
    def scan():
        return logged_in.post("/api/scans", data={"file": (io.BytesIO(b"same source"), "same.py")}, content_type="multipart/form-data")
    first = scan().get_json()["scan"]
    finding = logged_in.get("/api/findings").get_json()["findings"][0]
    present = scan().get_json()["scan"]
    conflict = logged_in.post(f"/api/findings/{finding['id']}/verify", json={"scan_id": present["id"]})
    assert conflict.status_code == 409
    clean = scan().get_json()["scan"]
    verified = logged_in.post(f"/api/findings/{finding['id']}/verify", json={"scan_id": clean["id"]})
    assert verified.status_code == 200
    assert verified.get_json()["finding"]["status"] == "resolved"
    assert verified.get_json()["verified_by_scan_id"] == clean["id"]
    assert clean["id"] > first["id"]


def test_incident_resolution_requires_notes_and_verified_finding(logged_in, monkeypatch):
    reports = [[{"RuleID": "generic-api-key", "Secret": "fake", "File": "src/app.py", "StartLine": 4, "Fingerprint": "stable-location-fingerprint"}], []]
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: reports.pop(0))
    first = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"source"), "same.py")}, content_type="multipart/form-data").get_json()["scan"]
    finding = logged_in.get("/api/findings").get_json()["findings"][0]
    created = logged_in.post("/api/incidents", json={"title": "Potential credential exposure", "finding_id": finding["id"]})
    assert created.status_code == 201
    incident = created.get_json()["incident"]
    assert logged_in.patch(f"/api/incidents/{incident['id']}", json={"status": "resolved", "resolution_notes": "removed"}).status_code == 409
    assert logged_in.patch(f"/api/incidents/{incident['id']}", json={"status": "investigating"}).status_code == 200
    assert logged_in.patch(f"/api/incidents/{incident['id']}", json={"status": "remediation_pending"}).status_code == 200
    assert logged_in.patch(f"/api/incidents/{incident['id']}", json={"status": "resolved"}).status_code == 400
    clean = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"source"), "same.py")}, content_type="multipart/form-data").get_json()["scan"]
    assert logged_in.post(f"/api/findings/{finding['id']}/verify", json={"scan_id": clean["id"]}).status_code == 200
    done = logged_in.patch(f"/api/incidents/{incident['id']}", json={"status": "resolved", "resolution_notes": "Removed and verified by clean scan."})
    assert done.status_code == 200
    assert done.get_json()["incident"]["status"] == "resolved"
    timeline = logged_in.get(f"/api/incidents/{incident['id']}/events").get_json()["events"]
    assert any(event["event_type"] == "status_changed" for event in timeline)
    timeline_response = logged_in.get(f"/api/incidents/{incident['id']}/events")
    assert timeline_response.status_code == 200
    assert timeline_response.get_json()["events"]
    audit = logged_in.get("/api/audit").get_json()["events"]
    assert any(event["action"] == "finding_verified_resolved" for event in audit)


def test_verification_must_use_later_scan_of_same_named_source(logged_in, monkeypatch):
    reports = [[{"RuleID": "generic-api-key", "Secret": "fake", "File": "app.py", "StartLine": 2, "Fingerprint": "same"}], []]
    monkeypatch.setattr("secretshield.scanner.run_gitleaks", lambda *args, **kwargs: reports.pop(0))
    first = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"source"), "original.py")}, content_type="multipart/form-data").get_json()["scan"]
    finding = logged_in.get("/api/findings").get_json()["findings"][0]
    other_source = logged_in.post("/api/scans", data={"file": (io.BytesIO(b"source"), "different.py")}, content_type="multipart/form-data").get_json()["scan"]
    response = logged_in.post(f"/api/findings/{finding['id']}/verify", json={"scan_id": other_source["id"]})
    assert response.status_code == 400
    assert first["id"] < other_source["id"]


def test_failed_incident_transition_does_not_persist_changes_or_audit(logged_in, app):
    created = logged_in.post("/api/incidents", json={"title": "Triage an exposure"}).get_json()["incident"]
    rejected = logged_in.patch(f"/api/incidents/{created['id']}", json={"status": "resolved", "resolution_notes": "not actually resolved"})
    assert rejected.status_code == 409
    state = logged_in.get("/api/incidents").get_json()["incidents"][0]
    assert state["status"] == "open"
    assert state["resolution_notes"] is None
    with app.app_context():
        from secretshield.models import AuditEvent
        assert not AuditEvent.query.filter_by(action="incident_updated").all()
