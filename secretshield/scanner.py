import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".txt", ".sh", ".ps1", ".tf", ".tfvars", ".xml", ".properties", ".pem", ".key", ".md", ".html", ".sql"}


class ScanError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def severity_for(rule_id):
    rule = rule_id.lower()
    if any(term in rule for term in ("private-key", "private_key", "aws-access-token", "aws-secret-key", "aws-secret-access-key", "github-pat", "gcp-service-account")):
        return "critical"
    if any(term in rule for term in ("aws", "token", "password", "secret", "api-key", "apikey", "slack", "stripe", "database")):
        return "high"
    if any(term in rule for term in ("generic", "jwt", "oauth", "credential")):
        return "medium"
    return "low"


def redact_report(report, root, key):
    if not isinstance(report, list):
        raise ScanError("invalid_scanner_report")
    findings = []
    root_path = Path(root).resolve()
    for item in report:
        if not isinstance(item, dict):
            raise ScanError("invalid_scanner_report")
        raw_path = str(item.get("File") or "").replace("\\", "/")
        if not raw_path:
            raise ScanError("invalid_scanner_report")
        path = Path(raw_path)
        if path.is_absolute():
            try:
                path = path.resolve().relative_to(root_path)
            except (ValueError, OSError) as exc:
                raise ScanError("invalid_scanner_report") from exc
        rel = PurePosixPath(path.as_posix().removeprefix("./"))
        if rel.is_absolute() or not rel.parts or ".." in rel.parts or not item.get("RuleID"):
            raise ScanError("invalid_scanner_report")
        rule_id = str(item["RuleID"])[:120]
        line = item.get("StartLine")
        try:
            line = int(line)
            if line < 1:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise ScanError("invalid_scanner_report") from exc
        gitleaks_fingerprint = str(item.get("Fingerprint") or "")
        # Fingerprint includes location/rule metadata but is keyed before persistence.
        material = (gitleaks_fingerprint or f"{rel}:{line}:{rule_id}").encode("utf-8", "replace")
        fingerprint = hmac.new(key, material, hashlib.sha256).hexdigest()
        findings.append({"fingerprint": fingerprint, "rule_id": rule_id,
                         "severity": severity_for(rule_id), "file_path": str(rel)[:1024],
                         "line_number": line})
    return findings


def extract_zip(archive_path, target_dir, max_files=1000, max_uncompressed=100 * 1024 * 1024):
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > max_files:
                raise ScanError("archive_too_many_files")
            total_size = 0
            safe = []
            for member in members:
                name = member.filename.replace("\\", "/")
                rel = PurePosixPath(name)
                mode = member.external_attr >> 16
                if rel.is_absolute() or ".." in rel.parts or not rel.parts or "" in rel.parts:
                    raise ScanError("archive_unsafe_path")
                if stat.S_ISLNK(mode):
                    raise ScanError("archive_symlink_rejected")
                if member.is_dir():
                    continue
                if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS and not Path(name).name.startswith(".") and ".git" not in rel.parts:
                    raise ScanError("unsupported_file_type")
                total_size += member.file_size
                if total_size > max_uncompressed:
                    raise ScanError("archive_uncompressed_size_limit")
                if member.file_size > 1024 * 1024 and member.file_size > max(1, member.compress_size) * 200:
                    raise ScanError("archive_suspicious_compression_ratio")
                safe.append(member)
            actual_total = 0
            for member in safe:
                destination = (Path(target_dir) / Path(*PurePosixPath(member.filename.replace("\\", "/")).parts)).resolve()
                if Path(target_dir).resolve() not in destination.parents:
                    raise ScanError("archive_unsafe_path")
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, open(destination, "wb") as dst:
                    while True:
                        chunk = src.read(64 * 1024)
                        if not chunk:
                            break
                        actual_total += len(chunk)
                        if actual_total > max_uncompressed or actual_total > max(1, member.file_size) + 1024:
                            raise ScanError("archive_uncompressed_size_limit")
                        dst.write(chunk)
    except zipfile.BadZipFile as exc:
        raise ScanError("invalid_zip") from exc


def run_gitleaks(source, binary="gitleaks", timeout=90, git_history=False, config_path=None):
    command = [binary, "git" if git_history else "dir", "--no-banner", "--no-color", "--log-level=fatal", "--redact"]
    if config_path:
        if not Path(config_path).is_file():
            raise ScanError("invalid_scanner_config")
        command.extend(["--config", str(config_path)])
    # Gitleaks v8.28.0 has no --timeout CLI flag; enforce the limit at the
    # subprocess boundary so we can safely terminate the scan if needed.
    command.extend(["--report-format", "json", "--report-path=-", "--exit-code", "0", str(source)])
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout + 5, check=False)
    except FileNotFoundError as exc:
        raise ScanError("gitleaks_unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError("scan_timeout") from exc
    if result.returncode != 0:
        raise ScanError("scanner_failed")
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ScanError("invalid_scanner_report") from exc


def scan_upload(file_storage, settings, fingerprint_key, include_git_history=False):
    filename = Path(file_storage.filename or "upload").name
    suffix = Path(filename).suffix.lower()
    is_dotfile = Path(filename).name.startswith(".") and Path(filename).name.lower() in {".env", ".gitignore", ".npmrc"}
    if suffix not in {".zip", *ALLOWED_EXTENSIONS} and not is_dotfile:
        raise ScanError("unsupported_file_type")
    temp_root = settings.get("SCAN_TEMP_DIR")
    if temp_root:
        Path(temp_root).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secretshield-", dir=temp_root) as temp:
        source = Path(temp) / "source"
        source.mkdir()
        uploaded = Path(temp) / filename
        file_storage.save(uploaded)
        if uploaded.stat().st_size > settings["MAX_SCAN_BYTES"]:
            raise ScanError("upload_too_large")
        if suffix == ".zip":
            extract_zip(uploaded, source, settings["MAX_ARCHIVE_FILES"])
        else:
            dest = source / Path(filename).name
            shutil.copyfile(uploaded, dest)
        if include_git_history:
            if not (source / ".git").is_dir():
                raise ScanError("git_history_requires_git_directory")
        raw = run_gitleaks(source, settings["GITLEAKS_PATH"], settings["SCAN_TIMEOUT_SECONDS"], include_git_history, settings.get("GITLEAKS_CONFIG"))
        return filename, redact_report(raw, source, fingerprint_key)
