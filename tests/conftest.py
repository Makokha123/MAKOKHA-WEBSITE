import os
import tempfile
import pytest
from flask import Flask

os.environ.setdefault("FLASK_ENV", "testing")

@pytest.fixture(scope="session")
def app():
    # Import after setting env
    from app import app as flask_app, db

    # Use in-memory DB for tests
    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SERVER_NAME": "localhost",
    })

    # Temporary upload directory
    tmpdir = tempfile.TemporaryDirectory()
    flask_app.config["UPLOAD_FOLDER"] = tmpdir.name

    with flask_app.app_context():
        db.create_all()

    yield flask_app

    # Teardown
    with flask_app.app_context():
        db.drop_all()
    tmpdir.cleanup()

@pytest.fixture()
def client(app):
    return app.test_client()
