from flask import Blueprint, render_template
from app.routes.auth import login_required
from app.services.network_collector import collector
from app.services.packet_analyzer import packet_analyzer

monitoring_bp = Blueprint("monitoring", __name__)


@monitoring_bp.route("/monitoring")
@login_required
def monitoring_dashboard():
    interfaces = collector.get_interfaces()
    snapshot = collector.get_snapshot()
    scapy_status = packet_analyzer.get_status()

    return render_template(
        "monitoring.html",
        active_page="monitoring",
        interfaces=interfaces,
        snapshot=snapshot,
        scapy_status=scapy_status,
    )


@monitoring_bp.route("/interfaces")
@login_required
def interfaces_page():
    interfaces = collector.get_interfaces()
    snapshot = collector.get_snapshot()

    return render_template(
        "interfaces.html",
        active_page="interfaces",
        interfaces=interfaces,
        snapshot=snapshot,
    )
