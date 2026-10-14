import pytest
from secretshield import create_app
from secretshield.extensions import db
from secretshield.models import User


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-key-not-for-production", "SQLALCHEMY_DATABASE_URI": "sqlite://",
                      "SCAN_TEMP_DIR": str(tmp_path / "scan-tmp"),
                      "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False})
    with app.app_context():
        db.create_all()
        user = User(username="tester")
        user.set_password("correct horse battery staple")
        db.session.add(user)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in(client):
    client.post("/login", data={"username": "tester", "password": "correct horse battery staple"})
    return client
