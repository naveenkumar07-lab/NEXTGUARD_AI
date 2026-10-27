from flask import Blueprint, render_template, request, make_response
from app.routes.auth import login_required
from app.services.report_service import report_service
from app.models import NetworkMetric

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
def reports_page():
    summary = report_service.get_executive_summary()
    return render_template(
        "reports.html",
        active_page="reports",
        summary=summary,
    )


@reports_bp.route("/history")
@login_required
def history_page():
    # Fetch recent metric data points for historical tables
    history_metrics = NetworkMetric.query.order_by(NetworkMetric.timestamp.desc()).limit(100).all()
    return render_template(
        "history.html",
        active_page="history",
        metrics=history_metrics,
    )


@reports_bp.route("/reports/printable")
@login_required
def printable_report():
    summary = report_service.get_executive_summary()
    recent_metrics = NetworkMetric.query.order_by(NetworkMetric.timestamp.desc()).limit(20).all()
    return render_template(
        "printable_report.html",
        summary=summary,
        metrics=recent_metrics,
    )
