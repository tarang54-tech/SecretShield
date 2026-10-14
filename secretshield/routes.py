import logging
import time
import csv
import io
from datetime import datetime, timezone
from flask import Blueprint, Response, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user, logout_user, login_required
from . import limiter
from .extensions import db
from .models import AuditEvent, Finding, Incident, IncidentEvent, Scan, User, utcnow
from .scanner import ScanError, scan_upload

log = logging.getLogger("secretshield")
auth = Blueprint("auth", __name__)
main = Blueprint("main", __name__)
scans = Blueprint("scans", __name__, url_prefix="/api")


@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            login_user(user, remember=False, fresh=True)
            return redirect(url_for("main.dashboard"))
        flash("Login failed. Check your username and password.", "error")
    return render_template("login.html")


@auth.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@main.get("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main.get("/dashboard")
@login_required
def dashboard():
    scans_list = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).limit(10).all()
    totals = {"scans": Scan.query.filter_by(user_id=current_user.id).count(),
              "findings": db.session.query(Finding.id).join(Scan, Finding.scan_id == Scan.id).filter(Scan.user_id == current_user.id).count(),
              "critical": db.session.query(Finding.id).join(Scan, Finding.scan_id == Scan.id).filter(Scan.user_id == current_user.id, Finding.severity == "critical").count(),
              "high": db.session.query(Finding.id).join(Scan, Finding.scan_id == Scan.id).filter(Scan.user_id == current_user.id, Finding.severity == "high").count()}
    return render_template("dashboard.html", scans=scans_list, totals=totals)


@main.get("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return jsonify(scan=serialize_scan(scan), findings=[serialize_finding(f) for f in scan.findings])


def serialize_scan(scan):
    return {"id": scan.id, "source_name": scan.source_name, "source_type": scan.source_type,
            "status": scan.status, "finding_count": scan.finding_count,
            "started_at": scan.started_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_ms": scan.duration_ms, "error_code": scan.error_code}


def serialize_finding(finding):
    return {"id": finding.id, "rule_id": finding.rule_id,
            "severity": finding.severity, "file_path": finding.file_path,
            "line_number": finding.line_number, "scan_id": finding.scan_id,
            "source_name": finding.scan.source_name, "source_type": finding.scan.source_type,
            "source_scan_status": finding.scan.status,
            "status": finding.status,
            "detected_at": finding.detected_at.isoformat(), "verified_scan_id": finding.verified_scan_id}


@scans.get("/scans")
@login_required
def list_scans():
    items = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).limit(100).all()
    return jsonify(scans=[serialize_scan(item) for item in items])


@scans.post("/scans")
@login_required
def create_scan():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify(error="Choose one source file or ZIP archive to scan."), 400
    if len(upload.filename) > 255:
        return jsonify(error="Filename is too long."), 400
    history = request.form.get("git_history") == "true"
    scan = Scan(user_id=current_user.id, source_name=upload.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
                source_type=("git-history" if history else "zip") if upload.filename.lower().endswith(".zip") else "file")
    db.session.add(scan)
    db.session.commit()
    audit("scan_started", "scan", scan.id)
    started = time.monotonic()
    try:
        _, results = scan_upload(upload, current_app.config, current_app.secret_key.encode(), history)
        for result in results:
            db.session.add(Finding(scan_id=scan.id, **result))
        scan.status = "completed"
        scan.finding_count = len(results)
    except ScanError as exc:
        scan.status = "failed"
        scan.error_code = exc.code
        log.warning("Scan %s failed: %s", scan.id, exc.code)
    except Exception as exc:
        scan.status = "failed"
        scan.error_code = "internal_scan_error"
        log.error("Scan %s failed (%s)", scan.id, type(exc).__name__)
    scan.completed_at = datetime.now(timezone.utc)
    scan.duration_ms = max(0, int((time.monotonic() - started) * 1000))
    db.session.commit()
    audit("scan_completed" if scan.status == "completed" else "scan_failed", "scan", scan.id)
    if scan.status == "failed":
        return jsonify(scan=serialize_scan(scan)), 422
    return jsonify(scan=serialize_scan(scan), findings=[serialize_finding(f) for f in scan.findings]), 201


@scans.get("/findings")
@login_required
def list_findings():
    query = Finding.query.join(Scan, Finding.scan_id == Scan.id).filter(Scan.user_id == current_user.id)
    severity = request.args.get("severity")
    status = request.args.get("status")
    if severity in {"critical", "high", "medium", "low"}:
        query = query.filter(Finding.severity == severity)
    if status in {"open", "acknowledged", "resolved"}:
        query = query.filter(Finding.status == status)
    return jsonify(findings=[serialize_finding(f) for f in query.order_by(Finding.detected_at.desc()).limit(500).all()])


@scans.get("/reports/findings.csv")
@login_required
def export_findings():
    query = Finding.query.join(Scan, Finding.scan_id == Scan.id).filter(Scan.user_id == current_user.id).order_by(Finding.detected_at.desc()).limit(10000)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["scan_id", "severity", "rule_id", "file_path", "line_number", "status", "detected_at"])
    for finding in query.all():
        # Prefix formula-like source paths and rule names to prevent spreadsheet formula execution.
        values = [finding.scan_id, finding.severity, finding.rule_id, finding.file_path, finding.line_number, finding.status, finding.detected_at.isoformat()]
        writer.writerow([("'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value) for value in values])
    return Response(stream.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=secretshield-findings-redacted.csv", "Cache-Control": "no-store"})


@scans.post("/findings/<int:finding_id>/acknowledge")
@login_required
def acknowledge_finding(finding_id):
    finding = Finding.query.join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == finding_id, Scan.user_id == current_user.id).first_or_404()
    if finding.status == "open":
        finding.status = "acknowledged"
        db.session.commit()
        audit("finding_acknowledged", "finding", finding.id)
    return jsonify(finding=serialize_finding(finding))


def audit(action, entity_type, entity_id):
    events = getattr(g, "pending_audit_events", None)
    if events is None:
        events = g.pending_audit_events = []
    events.append((action, entity_type, entity_id))


def persist_audit_events(response):
    events = getattr(g, "pending_audit_events", None)
    if events and current_user.is_authenticated and response.status_code < 400:
        try:
            db.session.add_all(
                AuditEvent(user_id=current_user.id, action=action, entity_type=entity_type, entity_id=entity_id)
                for action, entity_type, entity_id in events
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.exception("Could not persist audit event batch")
    elif events:
        db.session.rollback()
    return response


@scans.post("/findings/<int:finding_id>/verify")
@login_required
def verify_finding(finding_id):
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("scan_id"), int):
        return jsonify(error="Provide the ID of a later completed scan."), 400
    finding = Finding.query.join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == finding_id, Scan.user_id == current_user.id).first_or_404()
    verification = Scan.query.filter_by(id=body["scan_id"], user_id=current_user.id, status="completed").first()
    if not verification or verification.id <= finding.scan_id or verification.source_name != finding.scan.source_name or verification.source_type != finding.scan.source_type:
        return jsonify(error="Verification must use a later successful scan of the same source."), 400
    if Finding.query.filter_by(scan_id=verification.id, fingerprint=finding.fingerprint).first():
        return jsonify(error="The same finding is still present in the verification scan."), 409
    if finding.status == "resolved":
        return jsonify(finding=serialize_finding(finding), message="Finding was already verified resolved."), 200
    finding.status = "resolved"
    finding.verified_scan_id = verification.id
    db.session.commit()
    audit("finding_verified_resolved", "finding", finding.id)
    return jsonify(finding=serialize_finding(finding), verified_by_scan_id=verification.id)


def serialize_incident(incident):
    return {"id": incident.id, "finding_id": incident.finding_id, "title": incident.title,
            "severity": incident.severity, "status": incident.status,
            "resolution_notes": incident.resolution_notes,
            "created_at": incident.created_at.isoformat(), "updated_at": incident.updated_at.isoformat(),
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None}


@scans.get("/incidents")
@login_required
def list_incidents():
    items = Incident.query.filter_by(user_id=current_user.id).order_by(Incident.updated_at.desc()).limit(200).all()
    return jsonify(incidents=[serialize_incident(item) for item in items])


@scans.post("/incidents")
@login_required
def create_incident():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON incident title and optional finding_id are required."), 400
    title = body.get("title")
    if not isinstance(title, str) or not title.strip() or len(title.strip()) > 200:
        return jsonify(error="title must contain 1–200 characters."), 400
    finding = None
    if body.get("finding_id") is not None:
        if isinstance(body["finding_id"], bool) or not isinstance(body["finding_id"], int):
            return jsonify(error="finding_id must be an integer."), 400
        finding = Finding.query.join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == body["finding_id"], Scan.user_id == current_user.id).first()
        if not finding:
            return jsonify(error="Finding not found."), 404
    incident = Incident(user_id=current_user.id, finding_id=finding.id if finding else None,
                        title=title.strip(), severity=finding.severity if finding else "medium")
    db.session.add(incident)
    db.session.flush()
    db.session.add(IncidentEvent(incident_id=incident.id, user_id=current_user.id, event_type="created", message="Incident created"))
    db.session.commit()
    audit("incident_created", "incident", incident.id)
    return jsonify(incident=serialize_incident(incident)), 201


@scans.patch("/incidents/<int:incident_id>")
@login_required
def update_incident(incident_id):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="Provide a JSON status and/or resolution_notes."), 400
    incident = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first_or_404()
    notes = body.get("resolution_notes")
    if notes is not None and (not isinstance(notes, str) or len(notes) > 500):
        return jsonify(error="resolution_notes must be 500 characters or fewer."), 400
    if notes is not None:
        incident.resolution_notes = notes.strip()
    target = body.get("status", incident.status)
    if target == "resolved" and not (incident.resolution_notes or "").strip():
        db.session.rollback()
        return jsonify(error="Add resolution_notes before resolving the incident."), 400
    transitions = {"open": {"investigating"}, "investigating": {"remediation_pending", "open"},
                   "remediation_pending": {"investigating", "resolved"}, "resolved": {"reopened"},
                   "reopened": {"investigating"}}
    if target not in transitions and target != incident.status:
        db.session.rollback()
        return jsonify(error="Invalid incident status."), 400
    if target != incident.status:
        if target not in transitions.get(incident.status, set()):
            db.session.rollback()
            return jsonify(error="Invalid incident status transition."), 409
        if target == "resolved":
            if incident.finding_id:
                finding = db.session.get(Finding, incident.finding_id)
                if finding and finding.status != "resolved":
                    db.session.rollback()
                    return jsonify(error="Verify the related finding with a clean later scan before resolving."), 409
            incident.resolved_at = utcnow()
        elif target == "reopened":
            incident.resolved_at = None
        incident.status = target
        db.session.add(IncidentEvent(incident_id=incident.id, user_id=current_user.id, event_type="status_changed", message=f"Status changed to {target}"))
    elif notes is not None:
        db.session.add(IncidentEvent(incident_id=incident.id, user_id=current_user.id, event_type="notes_updated", message="Resolution notes updated"))
    db.session.commit()
    audit("incident_updated", "incident", incident.id)
    return jsonify(incident=serialize_incident(incident))


@scans.get("/incidents/<int:incident_id>/events")
@login_required
def incident_timeline(incident_id):
    incident = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first_or_404()
    events = [{"id": event.id, "event_type": event.event_type, "message": event.message,
               "created_at": event.created_at.isoformat()} for event in incident.events]
    return jsonify(incident_id=incident.id, events=events)


@scans.get("/audit")
@login_required
def audit_log():
    events = AuditEvent.query.filter_by(user_id=current_user.id).order_by(AuditEvent.id.desc()).limit(500).all()
    return jsonify(events=[{"action": event.action, "entity_type": event.entity_type,
                            "entity_id": event.entity_id, "created_at": event.created_at.isoformat()} for event in events])
