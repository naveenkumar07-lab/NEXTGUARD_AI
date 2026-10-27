import time
from app.services.network_collector import collector


def test_get_interfaces():
    """Test interface enumeration returns list with standard fields."""
    interfaces = collector.get_interfaces()
    assert isinstance(interfaces, list)
    if interfaces:
        first = interfaces[0]
        assert "name" in first
        assert "is_up" in first
        assert "ipv4" in first


def test_monitoring_start_and_stop_lifecycle(app):
    """Test starting and stopping collector thread without errors."""
    collector.stop_monitoring()  # Ensure stopped first
    assert not collector.is_active()

    start_res = collector.start_monitoring(app=app, is_demo=True, interval=0.5)
    assert start_res["success"] is True
    assert collector.is_active() is True

    # Test duplicate start is rejected safely
    dup_res = collector.start_monitoring(app=app, is_demo=True, interval=0.5)
    assert dup_res["success"] is False
    assert "already active" in dup_res["message"]

    time.sleep(1.0)
    snapshot = collector.get_snapshot()
    assert snapshot["is_monitoring"] is True
    assert snapshot["is_demo"] is True

    # Stop collector
    stop_res = collector.stop_monitoring()
    assert stop_res["success"] is True
    assert collector.is_active() is False


def test_monitoring_endpoints(auth_client):
    """Test start and stop endpoints via HTTP API."""
    # Ensure collector is stopped
    auth_client.post("/api/monitoring/stop")

    # Start via API
    res = auth_client.post("/api/monitoring/start", json={
        "is_demo": True,
        "interval": 1.0
    })
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Stop via API
    stop_res = auth_client.post("/api/monitoring/stop")
    assert stop_res.status_code == 200
    assert stop_res.get_json()["success"] is True
