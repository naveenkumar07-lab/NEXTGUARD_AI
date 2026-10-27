import pytest
from app import create_app
from app.extensions import db
from app.models import User
from app.services.network_collector import collector


@pytest.fixture
def app():
    # Ensure collector is stopped before test
    collector.stop_monitoring()

    app = create_app("testing")
    with app.app_context():
        # Ensure tables exist
        db.create_all()

        # Check if admin exists; if not create
        test_user = User.query.filter_by(username="admin").first()
        if not test_user:
            test_user = User(
                username="admin",
                email="admin@test.local",
                is_admin=True
            )
            test_user.set_password("admin123")
            db.session.add(test_user)
            db.session.commit()

        yield app

        # Clean up
        collector.stop_monitoring()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture
def auth_client(client):
    # Log in test user
    client.post("/login", data={
        "username": "admin",
        "password": "admin123"
    }, follow_redirects=True)
    return client
