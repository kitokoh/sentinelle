"""Auth roundtrip tests: register, login, me, wrong password."""

EMAIL = "analyst@sentinelle.dev"
PASSWORD = "AnalystPass2026!"


def test_register_login_me_roundtrip(client):
    # Register
    response = client.post("/api/auth/register", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 201, response.text
    register_token = response.json()["access_token"]
    assert response.json()["token_type"] == "bearer"

    # Login with the same credentials
    response = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 200, response.text
    login_token = response.json()["access_token"]

    # /me with the login token
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login_token}"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["email"] == EMAIL
    assert body["role"] == "analyst"

    # /me with the register token resolves to the same user
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {register_token}"})
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL


def test_login_wrong_password_401(client):
    response = client.post("/api/auth/login", json={"email": EMAIL, "password": "wrong-password"})
    assert response.status_code == 401


def test_me_without_token_401(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_duplicate_registration_400(client):
    payload = {"email": "dupe@sentinelle.dev", "password": "DupePass2026!"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 400
