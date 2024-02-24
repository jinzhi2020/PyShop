import pytest
from app import app
from app import User
from app import db


@pytest.fixture(scope="module", autouse=True)
def test_client():
    with app.test_client() as client:
        yield client
        User.query.filter_by(username='jerry2').delete()
        db.session.commit()


@pytest.mark.parametrize(("username", "password", "status_code"), [
    ("jerry2", "Xbcd20198$", 201),
    ("jerry2", "Xbcd20198$", 402),
])
def test_register(test_client, username, password, status_code):
    response = test_client.post("/register", json={
        "username": username,
        "password": password
    })
    assert response.status_code == status_code