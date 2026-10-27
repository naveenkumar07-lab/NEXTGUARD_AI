def test_app_startup_and_health(client):
    """Test public health endpoint without authentication."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "NetGuard AI"


def test_login_page_renders(client):
    """Test login page loads cleanly."""
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Operator Login" in response.data or b"NETGUARD" in response.data


def test_valid_login(client):
    """Test login with valid credentials."""
    response = client.post("/login", data={
        "username": "admin",
        "password": "admin123"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"SOC Telemetry Overview" in response.data


def test_invalid_login(client):
    """Test login with invalid password fails and shows error."""
    response = client.post("/login", data={
        "username": "admin",
        "password": "wrongpassword"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid credentials" in response.data


def test_unauthorized_redirect(client):
    """Test protected routes redirect unauthenticated users to login."""
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_unauthorized_api_returns_401(client):
    """Test protected API endpoints return 401 when unauthenticated."""
    response = client.get("/api/status")
    assert response.status_code == 401


def test_logout(auth_client):
    """Test logout clears session."""
    response = auth_client.get("/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"signed out safely" in response.data

    # Verify subsequent protected access is blocked
    dash_resp = auth_client.get("/dashboard")
    assert dash_resp.status_code == 302
