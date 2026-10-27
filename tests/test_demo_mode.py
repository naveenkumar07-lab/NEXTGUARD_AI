from app.services.demo_generator import demo_generator


def test_demo_generator_scenarios():
    """Test synthetic traffic generator produces realistic metrics across scenarios."""
    # 1. Normal Flow
    demo_generator.set_scenario("NORMAL")
    tick1 = demo_generator.generate_tick(elapsed_seconds=2.0)
    assert tick1["is_demo"] is True
    assert tick1["download_speed_mbps"] > 0
    assert tick1["upload_speed_mbps"] > 0
    assert tick1["packet_rate_pps"] > 0
    assert "protocols" in tick1

    # 2. Traffic Spike Scenario
    demo_generator.set_scenario("TRAFFIC_SPIKE")
    spike_tick = demo_generator.generate_tick(elapsed_seconds=2.0)
    assert spike_tick["download_speed_mbps"] >= 100.0  # Spikes above 100 Mbps

    # 3. Port Scan Scenario
    demo_generator.set_scenario("PORT_SCAN")
    scan_tick = demo_generator.generate_tick(elapsed_seconds=2.0)
    assert scan_tick["packet_rate_pps"] >= 3000.0  # High packet rate

    # 4. Data Exfiltration Scenario
    demo_generator.set_scenario("DATA_EXFILTRATION")
    exfil_tick = demo_generator.generate_tick(elapsed_seconds=2.0)
    assert exfil_tick["upload_speed_mbps"] >= 50.0  # Heavy outbound upload

    # 5. DDoS Scenario
    demo_generator.set_scenario("DDOS_ATTACK")
    ddos_tick = demo_generator.generate_tick(elapsed_seconds=2.0)
    assert ddos_tick["packet_rate_pps"] >= 6000.0  # Massive flood


def test_monotonic_byte_accumulation():
    """Test cumulative byte counters advance monotonically with each tick."""
    b_recv_start = demo_generator.cumulative_bytes_recv
    b_sent_start = demo_generator.cumulative_bytes_sent

    demo_generator.generate_tick(elapsed_seconds=1.0)

    assert demo_generator.cumulative_bytes_recv > b_recv_start
    assert demo_generator.cumulative_bytes_sent > b_sent_start
