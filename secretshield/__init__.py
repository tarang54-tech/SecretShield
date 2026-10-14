import os
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, jsonify, redirect, request, url_for
from flask_login import LoginManager, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFError, CSRFProtect
from .extensions import db
from .models import User

login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key and not test_config:
        raise RuntimeError("Set SECRET_KEY in the environment before starting SecretShield.")
    database_url = os.getenv("DATABASE_URL", "sqlite:///secretshield.db")
    # Render Postgres provides the generic URL scheme. This project installs
    # Psycopg 3, so make SQLAlchemy select that driver explicitly.
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    app.config.from_mapping(
        SECRET_KEY=secret_key or "test-only-key",
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_SCAN_BYTES", "20971520")) + 1024 * 1024,
        MAX_SCAN_BYTES=int(os.getenv("MAX_SCAN_BYTES", "20971520")),
        MAX_ARCHIVE_FILES=int(os.getenv("MAX_ARCHIVE_FILES", "1000")),
        SCAN_TIMEOUT_SECONDS=int(os.getenv("SCAN_TIMEOUT_SECONDS", "90")),
        GITLEAKS_PATH=os.getenv("GITLEAKS_PATH", "gitleaks"),
        GITLEAKS_CONFIG=os.getenv("GITLEAKS_CONFIG", str(Path(__file__).resolve().parent.parent / ".gitleaks.toml")),
        SCAN_TEMP_DIR=os.getenv("SCAN_TEMP_DIR", str(Path(app.instance_path) / "scan-tmp")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
        REMEMBER_COOKIE_HTTPONLY=True,
        WTF_CSRF_TIME_LIMIT=3600,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["SCAN_TEMP_DIR"], mode=0o700, exist_ok=True)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"
    csrf.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    from .routes import auth, main, scans, persist_audit_events
    app.register_blueprint(auth)
    app.register_blueprint(main)
    app.register_blueprint(scans)
    app.after_request(persist_audit_events)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="Authentication required"), 401
        return redirect(url_for("auth.login"))

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else response.headers.get("Cache-Control", "")
        return response

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", time=datetime.now(timezone.utc).isoformat())

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="CSRF validation failed"), 400
        return "Form expired. Reload and try again.", 400

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="Upload is too large. Maximum upload size is 20 MB."), 413

    @app.cli.command("create-admin")
    def create_admin():
        import click
        username = click.prompt("Administrator username")
        if User.query.filter_by(username=username).first():
            raise click.ClickException("That username already exists.")
        password = click.prompt("Administrator password", hide_input=True, confirmation_prompt=True)
        if len(password) < 12:
            raise click.ClickException("Use a password with at least 12 characters.")
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo("Administrator account created.")

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin():
        """Create the first administrator from deployment environment values."""
        import click
        if User.query.first():
            click.echo("An administrator is already initialized.")
            return
        username = os.getenv("ADMIN_USERNAME")
        password = os.getenv("ADMIN_PASSWORD")
        if not username or not password or len(password) < 12:
            raise click.ClickException(
                "For first-time setup, set ADMIN_USERNAME and an ADMIN_PASSWORD "
                "with at least 12 characters."
            )
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo("Initial administrator account created.")

    return app
