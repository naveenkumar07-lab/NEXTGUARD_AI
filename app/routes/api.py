from datetime import datetime, timezone
import psutil
from flask import Blueprint, jsonify, request, session, make_response, current_app
from app.extensions import db
from app.models import (
    NetworkMetric,
    AnomalyEvent,
    Alert,
    NetworkHealthLog,
    MonitoringSession,
    User,
)
from app.services.network_collector import collector
from app.services.anomaly_detector import anomaly_detector
from app.services.health_analyzer import health_analyzer
from app.services.demo_generator import demo_generator
from app.services.packet_analyzer import packet_analyzer
from app.services.report_service import report_service
from app.routes.auth import login_required

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/health", methods=["GET"])
def api_system_health():
    """
    Public health check endpoint returning system and service status.
    """
    return jsonify({
        "status": "healthy",
        "service": "NetGuard AI",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "monitoring_active": collector.is_active(),
        "is_demo_mode": collector.is_demo_mode,
        "active_interface": collector.active_interface,
    }), 200


@api_bp.route("/status", methods=["GET"])
@login_required
def api_status():
    """
    Returns high-level status of the collector, alert counts, and health score.
    """
    snapshot = collector.get_snapshot()
    active_alerts = Alert.query.filter_by(status="ACTIVE").count()
    total_anomalies = AnomalyEvent.query.count()

    latest_health = NetworkHealthLog.query.order_by(NetworkHealthLog.timestamp.desc()).first()
    health_score = latest_health.health_score if latest_health else 96.0

    return jsonify({
        "monitoring_active": collector.is_active(),
        "interface": collector.active_interface,
        "is_demo": collector.is_demo_mode,
        "active_alerts_count": active_alerts,
        "total_anomalies_count": total_anomalies,
        "health_score": round(health_score, 1),
        "snapshot": snapshot,
    }), 200


@api_bp.route("/interfaces", methods=["GET"])
@login_required
def api_interfaces():
    """
    Lists all detected host network interfaces with hardware and traffic counters.
    """
    interfaces = collector.get_interfaces()
    return jsonify({
        "interfaces": interfaces,
        "count": len(interfaces),
        "selected_interface": collector.active_interface
    }), 200


@api_bp.route("/metrics/current", methods=["GET"])
@login_required
def api_metrics_current():
    """
    Returns latest live snapshot of network transfer speeds and packet counters.
    """
    snapshot = collector.get_snapshot()
    return jsonify(snapshot), 200


@api_bp.route("/metrics/history", methods=["GET"])
@login_required
def api_metrics_history():
    """
    Returns historical telemetry points. Supports limit parameter and demo filter.
    """
    limit = min(300, int(request.args.get("limit", 60)))
    query = NetworkMetric.query

    # Optional filter by current session or data source
    if request.args.get("is_demo") is not None:
        is_demo_val = request.args.get("is_demo").lower() in ("1", "true")
        query = query.filter_by(is_demo=is_demo_val)

    metrics = query.order_by(NetworkMetric.timestamp.desc()).limit(limit).all()
    # Return chronologically ascending for charts
    data = [m.to_dict() for m in reversed(metrics)]
    return jsonify({
        "metrics": data,
        "count": len(data)
    }), 200


@api_bp.route("/monitoring/start", methods=["POST"])
@login_required
def api_monitoring_start():
    """
    Initiates monitoring session on requested interface or demo mode.
    """
    req_data = request.get_json(silent=True) or {}
    interface_name = req_data.get("interface")
    is_demo = bool(req_data.get("is_demo", False))
    interval = float(req_data.get("interval", 2.0))

    # Persist session in DB
    session_uuid = f"sess_{int(datetime.now(timezone.utc).timestamp())}"
    new_session = MonitoringSession(
        session_uuid=session_uuid,
        interface_name="DEMO-SYNTHETIC" if is_demo else (interface_name or "default"),
        is_demo=is_demo,
        is_active=True
    )
    db.session.add(new_session)
    db.session.commit()

    result = collector.start_monitoring(
        app=current_app._get_current_object(),
        interface_name=interface_name,
        is_demo=is_demo,
        interval=interval,
        session_uuid=session_uuid
    )

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@api_bp.route("/monitoring/stop", methods=["POST"])
@login_required
def api_monitoring_stop():
    """
    Stops the active background monitoring worker.
    """
    result = collector.stop_monitoring()
    
    # Update active session in DB
    if collector.session_uuid:
        sess = MonitoringSession.query.filter_by(session_uuid=collector.session_uuid).first()
        if sess:
            sess.is_active = False
            sess.stopped_at = datetime.now(timezone.utc)
            db.session.commit()

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@api_bp.route("/protocols", methods=["GET"])
@login_required
def api_protocols():
    """
    Returns current protocol traffic distribution.
    """
    snapshot = collector.get_snapshot()
    protocols = snapshot.get("protocols", {})
    return jsonify({
        "protocols": protocols,
        "timestamp": snapshot.get("timestamp"),
        "is_demo": snapshot.get("is_demo", False)
    }), 200


@api_bp.route("/anomalies", methods=["GET"])
@login_required
def api_anomalies():
    """
    Returns recorded anomaly events with severity, explanation, and troubleshooting steps.
    """
    limit = min(100, int(request.args.get("limit", 50)))
    anomalies = AnomalyEvent.query.order_by(AnomalyEvent.timestamp.desc()).limit(limit).all()
    return jsonify({
        "anomalies": [a.to_dict() for a in anomalies],
        "count": len(anomalies)
    }), 200


@api_bp.route("/alerts", methods=["GET"])
@login_required
def api_alerts():
    """
    Returns alerts filtered by status and severity.
    """
    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")
    limit = min(200, int(request.args.get("limit", 100)))

    query = Alert.query
    if status_filter:
        query = query.filter_by(status=status_filter.upper())
    if severity_filter:
        query = query.filter_by(severity=severity_filter.upper())

    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return jsonify({
        "alerts": [a.to_dict() for a in alerts],
        "count": len(alerts)
    }), 200


@api_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def api_alert_acknowledge(alert_id):
    """
    Marks an alert as ACKNOWLEDGED.
    """
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} acknowledged.",
        "alert": alert.to_dict()
    }), 200


@api_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def api_alert_resolve(alert_id):
    """
    Marks an alert as RESOLVED.
    """
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert.status = "RESOLVED"
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_by = session.get("username", "admin")
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} resolved.",
        "alert": alert.to_dict()
    }), 200


@api_bp.route("/connections", methods=["GET"])
@login_required
def api_connections():
    """
    Returns active local TCP/UDP socket connections.
    """
    connections_list = []
    try:
        raw_conns = psutil.net_connections(kind="inet")
        for c in raw_conns[:100]:
            proto = "TCP" if c.type == psutil.SOCK_STREAM else "UDP" if c.type == psutil.SOCK_DGRAM else "OTHER"
            local_addr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
            remote_addr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
            proc_name = "Unknown"
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    proc_name = p.name()
                except Exception:
                    pass

            connections_list.append({
                "proto": proto,
                "local_addr": local_addr,
                "remote_addr": remote_addr,
                "status": c.status if c.status else "NONE",
                "pid": c.pid,
                "process_name": proc_name,
            })
    except Exception as e:
        return jsonify({
            "connections": [],
            "error": "Access limited by operating system permissions.",
            "details": str(e)
        }), 200

    return jsonify({
        "connections": connections_list,
        "count": len(connections_list)
    }), 200


@api_bp.route("/reports/metrics.csv", methods=["GET"])
@login_required
def api_export_metrics_csv():
    """
    Downloads RFC-4180 CSV export of historical network metrics.
    """
    csv_content = report_service.generate_metrics_csv()
    response = make_response(csv_content)
    response.headers["Content-Disposition"] = "attachment; filename=netguard_metrics_export.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


@api_bp.route("/reports/alerts.csv", methods=["GET"])
@login_required
def api_export_alerts_csv():
    """
    Downloads RFC-4180 CSV export of alerts history.
    """
    csv_content = report_service.generate_alerts_csv()
    response = make_response(csv_content)
    response.headers["Content-Disposition"] = "attachment; filename=netguard_alerts_export.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


@api_bp.route("/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    """
    Gets or updates runtime settings.
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        down = data.get("download_threshold_mbps")
        up = data.get("upload_threshold_mbps")
        pps = data.get("packet_rate_threshold_pps")
        cooldown = data.get("alert_cooldown_seconds")
        interval = data.get("monitor_interval_seconds")

        anomaly_detector.set_thresholds(
            download_mbps=down,
            upload_mbps=up,
            packet_rate_pps=pps,
            cooldown=cooldown
        )
        if interval is not None:
            collector.interval = max(0.5, float(interval))

        return jsonify({"success": True, "message": "Settings updated."}), 200

    return jsonify({
        "download_threshold_mbps": anomaly_detector.download_threshold_mbps,
        "upload_threshold_mbps": anomaly_detector.upload_threshold_mbps,
        "packet_rate_threshold_pps": anomaly_detector.packet_rate_threshold_pps,
        "alert_cooldown_seconds": anomaly_detector.cooldown_seconds,
        "monitor_interval_seconds": collector.interval,
        "active_interface": collector.active_interface,
        "is_demo_mode": collector.is_demo_mode,
        "current_scenario": demo_generator.current_scenario,
    }), 200


@api_bp.route("/demo/scenario", methods=["POST"])
@login_required
def api_demo_scenario():
    """
    Switches active synthetic traffic scenario in Demonstration Mode.
    """
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "").upper()

    if demo_generator.set_scenario(scenario):
        return jsonify({
            "success": True,
            "scenario": demo_generator.current_scenario,
            "message": f"Demo scenario switched to {scenario}"
        }), 200
    else:
        return jsonify({
            "success": False,
            "error": "Invalid scenario. Choose from: NORMAL, TRAFFIC_SPIKE, PORT_SCAN, DATA_EXFILTRATION, DDOS_ATTACK"
        }), 400


@api_bp.route("/analytics/train-ml", methods=["POST"])
@login_required
def api_train_ml():
    """
    Trains or re-fits the unsupervised Isolation Forest baseline model.
    """
    data = request.get_json(silent=True) or {}
    contamination = float(data.get("contamination", 0.05))

    # Optional: collect actual recent metrics from DB as training input
    recent = NetworkMetric.query.order_by(NetworkMetric.timestamp.desc()).limit(150).all()
    samples = []
    if len(recent) >= 30:
        for r in recent:
            proto_tot = max(1, (r.tcp_packets + r.udp_packets + r.icmp_packets + r.dns_packets + r.https_packets))
            samples.append([
                r.download_speed_mbps,
                r.upload_speed_mbps,
                r.packet_rate_pps,
                r.tcp_packets / proto_tot,
                r.udp_packets / proto_tot,
            ])

    result = anomaly_detector.train_isolation_forest(
        training_data=samples if samples else None,
        contamination=contamination
    )

    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code


@api_bp.route("/health/check", methods=["POST"])
@login_required
def api_run_health_check():
    """
    Executes an on-demand network health diagnosis probe.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target_host", "8.8.8.8")
    
    result = health_analyzer.run_health_check(
        target_host=target,
        is_demo=collector.is_demo_mode
    )

    # Persist log to DB
    try:
        log = NetworkHealthLog(
            target_host=result["target_host"],
            health_score=result["health_score"],
            latency_ms=result["latency_ms"],
            jitter_ms=result["jitter_ms"],
            packet_loss_pct=result["packet_loss_pct"],
            status_label=result["status_label"],
            bottlenecks=result["bottlenecks"],
            recommendations=result["recommendations"],
            is_demo=result["is_demo"]
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

    return jsonify(result), 200


@api_bp.route("/packet-capture/status", methods=["GET"])
@login_required
def api_packet_capture_status():
    """
    Returns Scapy sniffer availability and status.
    """
    return jsonify(packet_analyzer.get_status()), 200


@api_bp.route("/packet-capture/start", methods=["POST"])
@login_required
def api_packet_capture_start():
    """
    Starts Scapy packet capture on chosen interface.
    """
    data = request.get_json(silent=True) or {}
    interface = data.get("interface") or collector.active_interface
    res = packet_analyzer.start_capture(interface_name=interface)
    return jsonify(res), (200 if res.get("success") else 400)


@api_bp.route("/packet-capture/stop", methods=["POST"])
@login_required
def api_packet_capture_stop():
    """
    Stops Scapy packet capture.
    """
    res = packet_analyzer.stop_capture()
    return jsonify(res), (200 if res.get("success") else 400)
