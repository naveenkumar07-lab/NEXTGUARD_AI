from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from app.routes.auth import login_required
from app.services.anomaly_detector import anomaly_detector
from app.services.network_collector import collector
from app.services.demo_generator import demo_generator
from app.models import User
from app.extensions import db

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    user = db.session.get(User, session["user_id"])

    if request.method == "POST":
        action = request.form.get("action")

        if action == "thresholds":
            try:
                down_mbps = float(request.form.get("download_threshold", 100))
                up_mbps = float(request.form.get("upload_threshold", 50))
                pps = float(request.form.get("packet_rate_threshold", 5000))
                cooldown = int(request.form.get("cooldown_seconds", 30))
                interval = float(request.form.get("monitor_interval", 2.0))

                anomaly_detector.set_thresholds(
                    download_mbps=down_mbps,
                    upload_mbps=up_mbps,
                    packet_rate_pps=pps,
                    cooldown=cooldown,
                )
                collector.interval = max(0.5, interval)

                flash("Detection thresholds and monitoring interval updated successfully.", "success")
            except ValueError:
                flash("Invalid numeric value provided for thresholds.", "danger")

        elif action == "password":
            current_pw = request.form.get("current_password")
            new_pw = request.form.get("new_password")
            confirm_pw = request.form.get("confirm_password")

            if not user.check_password(current_pw):
                flash("Current password verification failed.", "danger")
            elif new_pw != confirm_pw:
                flash("New passwords do not match.", "danger")
            elif len(new_pw) < 6:
                flash("New password must be at least 6 characters long.", "warning")
            else:
                user.set_password(new_pw)
                db.session.commit()
                flash("Password updated successfully.", "success")

        elif action == "demo_scenario":
            scenario = request.form.get("scenario")
            if demo_generator.set_scenario(scenario):
                flash(f"Simulation scenario switched to '{scenario}'.", "info")
            else:
                flash("Invalid scenario selection.", "danger")

        return redirect(url_for("settings.settings_page"))

    return render_template(
        "settings.html",
        active_page="settings",
        user=user,
        collector=collector,
        detector=anomaly_detector,
        demo_generator=demo_generator,
        scenarios=demo_generator.AVAILABLE_SCENARIOS,
    )
