from secretshield.extensions import db
from secretshield.models import User
from secretshield import create_app


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.location


def test_api_requires_login(client):
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/findings").status_code == 401


def test_login_success_and_failure(client):
    bad = client.post("/login", data={"username": "tester", "password": "wrong password"})
    assert bad.status_code == 200
    assert b"Login failed" in bad.data
    good = client.post("/login", data={"username": "tester", "password": "correct horse battery staple"})
    assert good.status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_password_is_hashed(app):
    with app.app_context():
        user = User.query.filter_by(username="tester").one()
        assert "correct horse battery staple" not in user.password_hash
        assert user.check_password("correct horse battery staple")


def test_render_postgres_url_selects_psycopg3(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@db.example:5432/app")
    app = create_app({"TESTING": True})
    assert app.config["SQLALCHEMY_DATABASE_URI"] == (
        "postgresql+psycopg://user:password@db.example:5432/app"
    )


def test_bootstrap_admin_is_idempotent_when_account_exists(app, monkeypatch):
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    result = app.test_cli_runner().invoke(args=["bootstrap-admin"])
    assert result.exit_code == 0
    assert "already initialized" in result.output


def test_state_change_rejects_missing_csrf():
    from secretshield import create_app
    from secretshield.extensions import db as test_db
    app = create_app({"TESTING": True, "SECRET_KEY": "csrf-test-key", "SQLALCHEMY_DATABASE_URI": "sqlite://", "RATELIMIT_ENABLED": False})
    with app.app_context():
        test_db.create_all()
    client = app.test_client()
    response = client.post("/login", data={"username": "x", "password": "y"})
    assert response.status_code == 400
