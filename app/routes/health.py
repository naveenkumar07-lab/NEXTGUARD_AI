from flask import Blueprint, render_template
from app.routes.auth import login_required
from app.services.health_analyzer import health_analyzer
from app.services.network_collector import collector
from app.models import NetworkHealthLog

health_bp = Blueprint("health", __name__)


@health_bp.route("/health")
@login_required
def health_page():
    # Fetch latest stored health check or run a live check
    latest_log = NetworkHealthLog.query.order_by(NetworkHealthLog.timestamp.desc()).first()
    recent_logs = NetworkHealthLog.query.order_by(NetworkHealthLog.timestamp.desc()).limit(20).all()

    # If no previous check exists, compute initial health reading
    if not latest_log:
        initial_check = health_analyzer.run_health_check(is_demo=collector.is_demo_mode)
    else:
        initial_check = latest_log.to_dict()

    return render_template(
        "health.html",
        active_page="health",
        current_health=initial_check,
        history=recent_logs,
    )
