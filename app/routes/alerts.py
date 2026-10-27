from flask import Blueprint, render_template, request
from app.routes.auth import login_required
from app.models import Alert

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/alerts")
@login_required
def alerts_page():
    severity_filter = request.args.get("severity", "ALL").upper()
    status_filter = request.args.get("status", "ALL").upper()
    search_query = request.args.get("q", "").strip().lower()

    query = Alert.query

    if severity_filter != "ALL":
        query = query.filter_by(severity=severity_filter)
    if status_filter != "ALL":
        query = query.filter_by(status=status_filter)

    alerts = query.order_by(Alert.timestamp.desc()).limit(200).all()

    if search_query:
        alerts = [
            a for a in alerts
            if search_query in a.title.lower() or search_query in a.description.lower() or search_query in a.category.lower()
        ]

    active_count = Alert.query.filter_by(status="ACTIVE").count()
    ack_count = Alert.query.filter_by(status="ACKNOWLEDGED").count()
    res_count = Alert.query.filter_by(status="RESOLVED").count()

    return render_template(
        "alerts.html",
        active_page="alerts",
        alerts=alerts,
        active_count=active_count,
        ack_count=ack_count,
        res_count=res_count,
        severity_filter=severity_filter,
        status_filter=status_filter,
        search_query=search_query,
    )
