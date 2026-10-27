from flask import Blueprint, render_template
from app.routes.auth import login_required
from app.services.anomaly_detector import anomaly_detector
from app.models import AnomalyEvent

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/analytics")
@login_required
def analytics_page():
    anomalies = AnomalyEvent.query.order_by(AnomalyEvent.timestamp.desc()).limit(50).all()

    ml_status = {
        "is_trained": anomaly_detector.is_model_trained,
        "sample_count": anomaly_detector.training_sample_count,
        "last_trained": anomaly_detector.last_trained_at,
        "features": anomaly_detector.feature_names,
    }

    return render_template(
        "analytics.html",
        active_page="analytics",
        anomalies=anomalies,
        ml_status=ml_status,
        thresholds={
            "download_mbps": anomaly_detector.download_threshold_mbps,
            "upload_mbps": anomaly_detector.upload_threshold_mbps,
            "packet_rate_pps": anomaly_detector.packet_rate_threshold_pps,
            "cooldown_sec": anomaly_detector.cooldown_seconds,
        },
    )
