import csv
import io
from datetime import datetime, timezone
from sqlalchemy import func
from app.models import NetworkMetric, Alert, AnomalyEvent, NetworkHealthLog


class ReportService:
    """
    Handles aggregation, statistical auditing, and export of network monitoring
    data into RFC-4180 compliant CSV formats and printable executive summaries.
    """

    @staticmethod
    def generate_metrics_csv(query_limit: int = 2000, is_demo_filter=None):
        """
        Generates CSV text buffer of recent network metrics.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            "Metric_ID",
            "Timestamp_UTC",
            "Interface",
            "Data_Source",
            "Download_Speed_Mbps",
            "Upload_Speed_Mbps",
            "Packet_Rate_PPS",
            "Bytes_Received",
            "Bytes_Sent",
            "Packets_Received",
            "Packets_Sent",
            "TCP_Packets",
            "UDP_Packets",
            "ICMP_Packets",
            "DNS_Packets",
            "HTTPS_Packets",
        ])

        query = NetworkMetric.query
        if is_demo_filter is not None:
            query = query.filter_by(is_demo=is_demo_filter)

        records = query.order_by(NetworkMetric.timestamp.desc()).limit(query_limit).all()

        for r in reversed(records):
            writer.writerow([
                r.id,
                r.timestamp.isoformat() if r.timestamp else "",
                r.interface_name,
                "SIMULATED_DEMO" if r.is_demo else "REAL_INTERFACE",
                f"{r.download_speed_mbps:.3f}",
                f"{r.upload_speed_mbps:.3f}",
                f"{r.packet_rate_pps:.1f}",
                r.bytes_recv,
                r.bytes_sent,
                r.packets_recv,
                r.packets_sent,
                r.tcp_packets,
                r.udp_packets,
                r.icmp_packets,
                r.dns_packets,
                r.https_packets,
            ])

        output.seek(0)
        return output.getvalue()

    @staticmethod
    def generate_alerts_csv(query_limit: int = 1000):
        """
        Generates CSV text buffer of recorded alerts.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Alert_ID",
            "Timestamp_UTC",
            "Severity",
            "Category",
            "Status",
            "Data_Source",
            "Title",
            "Description",
            "Acknowledged_At",
            "Resolved_At",
            "Resolved_By",
        ])

        alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(query_limit).all()

        for a in alerts:
            writer.writerow([
                a.id,
                a.timestamp.isoformat() if a.timestamp else "",
                a.severity,
                a.category,
                a.status,
                "DEMO" if a.is_demo else "REAL",
                a.title,
                a.description,
                a.acknowledged_at.isoformat() if a.acknowledged_at else "",
                a.resolved_at.isoformat() if a.resolved_at else "",
                a.resolved_by or "",
            ])

        output.seek(0)
        return output.getvalue()

    @staticmethod
    def get_executive_summary():
        """
        Computes statistical aggregate indicators for the executive report.
        """
        from app.extensions import db

        total_metrics = db.session.query(func.count(NetworkMetric.id)).scalar() or 0
        avg_down = db.session.query(func.avg(NetworkMetric.download_speed_mbps)).scalar() or 0.0
        max_down = db.session.query(func.max(NetworkMetric.download_speed_mbps)).scalar() or 0.0
        avg_up = db.session.query(func.avg(NetworkMetric.upload_speed_mbps)).scalar() or 0.0
        max_up = db.session.query(func.max(NetworkMetric.upload_speed_mbps)).scalar() or 0.0
        avg_pps = db.session.query(func.avg(NetworkMetric.packet_rate_pps)).scalar() or 0.0

        total_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
        active_alerts = db.session.query(func.count(Alert.id)).filter(Alert.status == "ACTIVE").scalar() or 0
        crit_alerts = db.session.query(func.count(Alert.id)).filter(Alert.severity == "CRITICAL").scalar() or 0
        high_alerts = db.session.query(func.count(Alert.id)).filter(Alert.severity == "HIGH").scalar() or 0
        med_alerts = db.session.query(func.count(Alert.id)).filter(Alert.severity == "MEDIUM").scalar() or 0

        latest_health = NetworkHealthLog.query.order_by(NetworkHealthLog.timestamp.desc()).first()
        latest_health_score = latest_health.health_score if latest_health else 95.0

        earliest_metric = NetworkMetric.query.order_by(NetworkMetric.timestamp.asc()).first()
        latest_metric = NetworkMetric.query.order_by(NetworkMetric.timestamp.desc()).first()

        period_start = earliest_metric.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if earliest_metric and earliest_metric.timestamp else "N/A"
        period_end = latest_metric.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_metric and latest_metric.timestamp else "N/A"

        return {
            "period_start": period_start,
            "period_end": period_end,
            "total_metrics_collected": total_metrics,
            "avg_download_mbps": round(avg_down, 2),
            "max_download_mbps": round(max_down, 2),
            "avg_upload_mbps": round(avg_up, 2),
            "max_upload_mbps": round(max_up, 2),
            "avg_packet_rate_pps": round(avg_pps, 1),
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "critical_alerts": crit_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": med_alerts,
            "latest_health_score": round(latest_health_score, 1),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }


report_service = ReportService()
