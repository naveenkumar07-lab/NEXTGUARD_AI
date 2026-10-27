from flask import Blueprint, render_template
from app.routes.auth import login_required
from app.services.network_collector import collector
from app.services.demo_generator import demo_generator
from app.models import Alert, AnomalyEvent

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    snapshot = collector.get_snapshot()
    active_alerts_count = Alert.query.filter_by(status="ACTIVE").count()
    recent_anomalies = AnomalyEvent.query.order_by(AnomalyEvent.timestamp.desc()).limit(5).all()

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        snapshot=snapshot,
        active_alerts_count=active_alerts_count,
        recent_anomalies=recent_anomalies,
        current_scenario=demo_generator.current_scenario,
    )
