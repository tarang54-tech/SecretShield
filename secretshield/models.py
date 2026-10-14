from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from .extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    source_name = db.Column(db.String(255), nullable=False)
    source_type = db.Column(db.String(24), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="running")
    finding_count = db.Column(db.Integer, nullable=False, default=0)
    started_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))
    duration_ms = db.Column(db.Integer)
    error_code = db.Column(db.String(64))
    findings = db.relationship(
        "Finding",
        backref="scan",
        cascade="all, delete-orphan",
        lazy=True,
        foreign_keys="Finding.scan_id",
    )


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = db.Column(db.String(64), nullable=False, index=True)
    rule_id = db.Column(db.String(120), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    file_path = db.Column(db.String(1024), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open")
    detected_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    verified_scan_id = db.Column(db.Integer, db.ForeignKey("scan.id", ondelete="SET NULL"))
    verified_scan = db.relationship("Scan", foreign_keys=[verified_scan_id])
    __table_args__ = (db.UniqueConstraint("scan_id", "fingerprint", name="uq_scan_finding_fingerprint"),)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("finding.id", ondelete="SET NULL"), index=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="open")
    resolution_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime(timezone=True))
    events = db.relationship("IncidentEvent", backref="incident", cascade="all, delete-orphan", order_by="IncidentEvent.id")


class IncidentEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    event_type = db.Column(db.String(40), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    action = db.Column(db.String(80), nullable=False)
    entity_type = db.Column(db.String(40), nullable=False)
    entity_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
