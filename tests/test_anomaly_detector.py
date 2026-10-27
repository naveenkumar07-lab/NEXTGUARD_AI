from app.services.anomaly_detector import anomaly_detector
from app.models import NetworkMetric, AnomalyEvent, Alert
from app.extensions import db


def test_rule_based_download_spike(app):
    """Test rule-based engine flags download exceeding threshold."""
    with app.app_context():
        anomaly_detector.set_thresholds(download_mbps=100.0, cooldown=0)

        metric = NetworkMetric(
            interface_name="test_eth0",
            download_speed_mbps=155.0,  # Exceeds 100 Mbps
            upload_speed_mbps=5.0,
            packet_rate_pps=400.0,
            is_demo=False
        )
        db.session.add(metric)
        db.session.commit()

        count = anomaly_detector.evaluate_metric(metric, is_demo=False)
        assert count >= 1

        event = AnomalyEvent.query.filter_by(metric_name="download_speed_mbps").first()
        assert event is not None
        assert event.observed_value == 155.0
        assert event.severity == "HIGH"
        assert "High Inbound Bandwidth" in event.title


def test_rule_based_upload_spike(app):
    """Test rule-based engine flags upload exceeding threshold (exfiltration pattern)."""
    with app.app_context():
        anomaly_detector.set_thresholds(upload_mbps=50.0, cooldown=0)

        metric = NetworkMetric(
            interface_name="test_eth0",
            download_speed_mbps=10.0,
            upload_speed_mbps=85.0,  # Exceeds 50 Mbps
            packet_rate_pps=600.0,
            is_demo=False
        )
        db.session.add(metric)
        db.session.commit()

        count = anomaly_detector.evaluate_metric(metric, is_demo=False)
        assert count >= 1

        event = AnomalyEvent.query.filter_by(metric_name="upload_speed_mbps").first()
        assert event is not None
        assert "Exfiltration" in event.explanation or "Outbound" in event.title


def test_isolation_forest_training_and_inference(app):
    """Test scikit-learn Isolation Forest baseline fitting and outlier inference."""
    with app.app_context():
        res = anomaly_detector.train_isolation_forest(contamination=0.05)
        assert res["success"] is True
        assert anomaly_detector.is_model_trained is True

        # Normal metric evaluation should not trigger extreme anomaly
        metric_normal = NetworkMetric(
            interface_name="eth0",
            download_speed_mbps=14.0,
            upload_speed_mbps=3.5,
            packet_rate_pps=320.0,
            tcp_packets=80,
            udp_packets=15,
            is_demo=False
        )
        db.session.add(metric_normal)
        db.session.commit()

        # Extreme outlier metric (e.g. 500 Mbps and 12,000 pps)
        metric_extreme = NetworkMetric(
            interface_name="eth0",
            download_speed_mbps=500.0,
            upload_speed_mbps=300.0,
            packet_rate_pps=15000.0,
            tcp_packets=900,
            udp_packets=8000,
            is_demo=False
        )
        db.session.add(metric_extreme)
        db.session.commit()

        anomaly_detector.cooldown_seconds = 0
        anomaly_detector.evaluate_metric(metric_extreme, is_demo=False)

        # Check if an alert was persisted
        alerts = Alert.query.all()
        assert len(alerts) > 0


def test_alert_suppression_cooldown(app):
    """Test duplicate alerts within cooldown window are suppressed."""
    with app.app_context():
        anomaly_detector.set_thresholds(download_mbps=100.0, cooldown=60)
        anomaly_detector._last_alert_times.clear()

        metric1 = NetworkMetric(
            interface_name="test0",
            download_speed_mbps=120.0,
            upload_speed_mbps=5.0,
            packet_rate_pps=300.0,
            is_demo=False
        )
        count1 = anomaly_detector.evaluate_metric(metric1, is_demo=False)
        assert count1 >= 1

        # Second identical spike immediately after should be suppressed
        metric2 = NetworkMetric(
            interface_name="test0",
            download_speed_mbps=125.0,
            upload_speed_mbps=5.0,
            packet_rate_pps=300.0,
            is_demo=False
        )
        count2 = anomaly_detector.evaluate_metric(metric2, is_demo=False)
        assert count2 == 0  # Suppressed by cooldown
