def test_api_status(auth_client):
    res = auth_client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "monitoring_active" in data
    assert "health_score" in data


def test_api_interfaces(auth_client):
    res = auth_client.get("/api/interfaces")
    assert res.status_code == 200
    data = res.get_json()
    assert "interfaces" in data
    assert "count" in data


def test_api_metrics_current_and_history(auth_client):
    res = auth_client.get("/api/metrics/current")
    assert res.status_code == 200
    data = res.get_json()
    assert "download_speed_bps" in data
    assert "upload_speed_bps" in data

    hist_res = auth_client.get("/api/metrics/history?limit=10")
    assert hist_res.status_code == 200
    assert "metrics" in hist_res.get_json()


def test_api_protocols(auth_client):
    res = auth_client.get("/api/protocols")
    assert res.status_code == 200
    data = res.get_json()
    assert "protocols" in data


def test_api_connections(auth_client):
    res = auth_client.get("/api/connections")
    assert res.status_code == 200
    data = res.get_json()
    assert "connections" in data


def test_api_settings_update(auth_client):
    res = auth_client.get("/api/settings")
    assert res.status_code == 200

    update_res = auth_client.post("/api/settings", json={
        "download_threshold_mbps": 120.0,
        "upload_threshold_mbps": 60.0,
        "packet_rate_threshold_pps": 6000.0,
        "alert_cooldown_seconds": 45,
        "monitor_interval_seconds": 2.5
    })
    assert update_res.status_code == 200
    assert update_res.get_json()["success"] is True


def test_api_demo_scenario_switch(auth_client):
    # Valid scenario switch
    res = auth_client.post("/api/demo/scenario", json={"scenario": "TRAFFIC_SPIKE"})
    assert res.status_code == 200
    assert res.get_json()["scenario"] == "TRAFFIC_SPIKE"

    # Invalid scenario switch
    inv_res = auth_client.post("/api/demo/scenario", json={"scenario": "NONEXISTENT_ATTACK"})
    assert inv_res.status_code == 400
    assert "Invalid scenario" in inv_res.get_json()["error"]


def test_api_health_check_probe(auth_client):
    res = auth_client.post("/api/health/check", json={"target_host": "127.0.0.1"})
    assert res.status_code == 200
    data = res.get_json()
    assert "health_score" in data
    assert "status_label" in data


def test_api_packet_capture_status(auth_client):
    res = auth_client.get("/api/packet-capture/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "is_capturing" in data
    assert "protocol_counts" in data
