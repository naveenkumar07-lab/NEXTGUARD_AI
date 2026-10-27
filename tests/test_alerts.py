from app.models import Alert
from app.extensions import db


def test_alert_lifecycle_and_api(auth_client, app):
    """Test acknowledging and resolving alerts."""
    with app.app_context():
        alert = Alert(
            title="Suspicious Outbound Activity",
            description="High upload bandwidth detected.",
            severity="HIGH",
            category="EGRESS_SURGE",
            status="ACTIVE",
            is_demo=False
        )
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id

    # 1. Fetch alerts list
    res = auth_client.get("/api/alerts?status=ACTIVE")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] >= 1
    assert any(a["id"] == alert_id for a in data["alerts"])

    # 2. Acknowledge alert
    ack_res = auth_client.post(f"/api/alerts/{alert_id}/acknowledge")
    assert ack_res.status_code == 200
    ack_data = ack_res.get_json()
    assert ack_data["alert"]["status"] == "ACKNOWLEDGED"

    # 3. Resolve alert
    res_res = auth_client.post(f"/api/alerts/{alert_id}/resolve")
    assert res_res.status_code == 200
    res_data = res_res.get_json()
    assert res_data["alert"]["status"] == "RESOLVED"
    assert res_data["alert"]["resolved_by"] == "admin"


def test_invalid_alert_id(auth_client):
    """Test 404 response on nonexistent alert acknowledge/resolve."""
    res = auth_client.post("/api/alerts/999999/acknowledge")
    assert res.status_code == 404
