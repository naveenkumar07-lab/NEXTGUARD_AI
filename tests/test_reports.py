import csv
import io
from app.models import NetworkMetric, Alert
from app.extensions import db
from app.services.report_service import report_service


def test_csv_metrics_export(auth_client, app):
    """Test metrics CSV export produces valid CSV with expected columns."""
    with app.app_context():
        m = NetworkMetric(
            interface_name="eth0",
            download_speed_mbps=45.2,
            upload_speed_mbps=12.1,
            packet_rate_pps=520.0,
            is_demo=False
        )
        db.session.add(m)
        db.session.commit()

    res = auth_client.get("/api/reports/metrics.csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["Content-Type"]

    content = res.data.decode("utf-8")
    reader = csv.reader(io.StringIO(content))
    header = next(reader)
    assert "Metric_ID" in header
    assert "Download_Speed_Mbps" in header
    assert "Upload_Speed_Mbps" in header


def test_csv_alerts_export(auth_client, app):
    """Test alerts CSV export produces valid CSV."""
    with app.app_context():
        a = Alert(
            title="Spike in outbound traffic",
            description="Exceeded 50 Mbps",
            severity="HIGH",
            category="EGRESS_SURGE",
            is_demo=False
        )
        db.session.add(a)
        db.session.commit()

    res = auth_client.get("/api/reports/alerts.csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["Content-Type"]

    content = res.data.decode("utf-8")
    reader = csv.reader(io.StringIO(content))
    header = next(reader)
    assert "Alert_ID" in header
    assert "Severity" in header
    assert "Category" in header


def test_executive_summary_service(app):
    """Test report service computes statistical aggregates cleanly."""
    with app.app_context():
        summary = report_service.get_executive_summary()
        assert "total_metrics_collected" in summary
        assert "avg_download_mbps" in summary
        assert "max_download_mbps" in summary
        assert "latest_health_score" in summary
