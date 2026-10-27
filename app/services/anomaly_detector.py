import time
import logging
from datetime import datetime, timezone
from collections import deque
import numpy as np

logger = logging.getLogger(__name__)

# Scikit-learn Isolation Forest import
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not imported. Fallback mode will use rule-based detection.")


class AnomalyDetector:
    """
    Intelligent dual-mode anomaly detection engine:
    1. Deterministic Rule-Based Engine (thresholds, rate spikes, protocol imbalance)
    2. Unsupervised Machine Learning Engine (scikit-learn Isolation Forest)
    Includes alert cooldown suppression to eliminate alert storms.
    """

    def __init__(self):
        # Configuration thresholds
        self.download_threshold_mbps = 100.0
        self.upload_threshold_mbps = 50.0
        self.packet_rate_threshold_pps = 5000.0
        self.cooldown_seconds = 30
        
        # Recent traffic rolling window for spike calculation
        self._history_window = deque(maxlen=60)  # last 60 ticks
        
        # Cooldown map: category -> last_triggered_timestamp
        self._last_alert_times = {}

        # Machine Learning model state
        self.ml_model = None
        self.is_model_trained = False
        self.training_sample_count = 0
        self.last_trained_at = None
        self.feature_names = ["download_speed_mbps", "upload_speed_mbps", "packet_rate_pps", "tcp_ratio", "udp_ratio"]

    def set_thresholds(self, download_mbps=None, upload_mbps=None, packet_rate_pps=None, cooldown=None):
        if download_mbps is not None:
            self.download_threshold_mbps = float(download_mbps)
        if upload_mbps is not None:
            self.upload_threshold_mbps = float(upload_mbps)
        if packet_rate_pps is not None:
            self.packet_rate_threshold_pps = float(packet_rate_pps)
        if cooldown is not None:
            self.cooldown_seconds = int(cooldown)

    def train_isolation_forest(self, training_data=None, contamination=0.05):
        """
        Trains or fits an Isolation Forest model on baseline traffic samples.
        If training_data is None, generates synthetic baseline data based on typical network behavior.
        """
        if not SKLEARN_AVAILABLE:
            return {"success": False, "message": "scikit-learn is not available in environment."}

        try:
            if training_data is None or len(training_data) < 20:
                # Generate a healthy baseline distribution of 200 normal network samples
                np.random.seed(42)
                n_samples = 200
                # Normal download: 5-25 Mbps, upload: 1-10 Mbps, packet rate: 100-800 pps, tcp: 0.7-0.9, udp: 0.05-0.25
                normal_down = np.random.normal(loc=15.0, scale=5.0, size=n_samples).clip(0.1, 50.0)
                normal_up = np.random.normal(loc=4.0, scale=2.0, size=n_samples).clip(0.05, 20.0)
                normal_pps = np.random.normal(loc=350.0, scale=120.0, size=n_samples).clip(20.0, 1500.0)
                normal_tcp = np.random.normal(loc=0.8, scale=0.08, size=n_samples).clip(0.4, 0.98)
                normal_udp = np.random.normal(loc=0.15, scale=0.06, size=n_samples).clip(0.01, 0.5)

                X = np.column_stack([normal_down, normal_up, normal_pps, normal_tcp, normal_udp])
            else:
                X = np.array(training_data)

            # Fit Isolation Forest
            model = IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=42
            )
            model.fit(X)

            self.ml_model = model
            self.is_model_trained = True
            self.training_sample_count = len(X)
            self.last_trained_at = datetime.now(timezone.utc).isoformat()

            return {
                "success": True,
                "message": f"Isolation Forest trained successfully on {len(X)} baseline samples.",
                "samples": len(X),
                "features": self.feature_names
            }
        except Exception as e:
            logger.error(f"Error training Isolation Forest: {e}")
            return {"success": False, "message": f"Model training failed: {str(e)}"}

    def _should_suppress(self, alert_key: str) -> bool:
        """
        Prevents alert flooding by enforcing a cooldown window for duplicate categories.
        """
        now = time.time()
        last_time = self._last_alert_times.get(alert_key, 0)
        if (now - last_time) < self.cooldown_seconds:
            return True
        self._last_alert_times[alert_key] = now
        return False

    def evaluate_metric(self, metric_row, session_id=None, is_demo=False):
        """
        Evaluates a newly collected metric row against:
        1. Rule-based triggers
        2. Machine Learning Isolation Forest model (if trained)
        Persists detected anomalies and alerts into database.
        """
        from app.extensions import db
        from app.models import AnomalyEvent, Alert

        down_mbps = metric_row.download_speed_mbps
        up_mbps = metric_row.upload_speed_mbps
        pps = metric_row.packet_rate_pps
        total_packets = (metric_row.packets_recv or 0) + (metric_row.packets_sent or 0)
        
        # Calculate protocol ratios safely
        tcp_count = metric_row.tcp_packets or 0
        udp_count = metric_row.udp_packets or 0
        icmp_count = metric_row.icmp_packets or 0
        dns_count = metric_row.dns_packets or 0
        http_count = metric_row.http_packets or 0
        https_count = metric_row.https_packets or 0
        other_count = metric_row.other_packets or 0

        proto_total = max(1, (tcp_count + udp_count + icmp_count + dns_count + http_count + https_count + other_count))
        tcp_ratio = tcp_count / proto_total
        udp_ratio = udp_count / proto_total

        # Keep rolling history for sudden surge detection
        self._history_window.append({
            "down_mbps": down_mbps,
            "up_mbps": up_mbps,
            "pps": pps
        })

        anomalies_to_add = []

        # ==========================================
        # 1. RULE-BASED DETECTION
        # ==========================================

        # A. Download Throughput Breach
        if down_mbps > self.download_threshold_mbps:
            key = "DOWNLOAD_THRESHOLD_BREACH"
            if not self._should_suppress(key):
                anomalies_to_add.append({
                    "severity": "HIGH",
                    "detection_method": "RULE_BASED",
                    "metric_name": "download_speed_mbps",
                    "observed_value": down_mbps,
                    "threshold_value": self.download_threshold_mbps,
                    "title": "High Inbound Bandwidth Exceeded",
                    "explanation": f"Inbound download throughput reached {down_mbps:.2f} Mbps, exceeding threshold of {self.download_threshold_mbps:.2f} Mbps.",
                    "recommendation": "Identify heavy processes or inspect local interfaces for large download activity or streaming transfers.",
                    "category": key
                })

        # B. Upload Throughput Breach (Data Exfiltration Indicator)
        if up_mbps > self.upload_threshold_mbps:
            key = "UPLOAD_THRESHOLD_BREACH"
            if not self._should_suppress(key):
                anomalies_to_add.append({
                    "severity": "CRITICAL" if up_mbps > self.upload_threshold_mbps * 2 else "HIGH",
                    "detection_method": "RULE_BASED",
                    "metric_name": "upload_speed_mbps",
                    "observed_value": up_mbps,
                    "threshold_value": self.upload_threshold_mbps,
                    "title": "Suspicious Outbound Bandwidth Surge",
                    "explanation": f"Outbound upload throughput surged to {up_mbps:.2f} Mbps (threshold: {self.upload_threshold_mbps:.2f} Mbps). Possible heavy egress or data exfiltration pattern.",
                    "recommendation": "Inspect active outbound network sockets in Connections tab to isolate the transmitting process PID.",
                    "category": key
                })

        # C. Packet Rate Spike (DDoS / Flood Indicator)
        if pps > self.packet_rate_threshold_pps:
            key = "PACKET_FLOOD_SPIKE"
            if not self._should_suppress(key):
                anomalies_to_add.append({
                    "severity": "CRITICAL",
                    "detection_method": "RULE_BASED",
                    "metric_name": "packet_rate_pps",
                    "observed_value": pps,
                    "threshold_value": self.packet_rate_threshold_pps,
                    "title": "Severe Packet Rate Spike Detected",
                    "explanation": f"Packet transfer rate escalated to {pps:.0f} packets/sec, exceeding configured threshold ({self.packet_rate_threshold_pps:.0f} pps).",
                    "recommendation": "Check for network flood, broadcast storms, or excessive socket connections on open ports.",
                    "category": key
                })

        # D. Sudden Surge Relative to Rolling Baseline (> 4x mean of last 30 readings)
        if len(self._history_window) >= 15:
            past_downs = [x["down_mbps"] for x in list(self._history_window)[:-1]]
            mean_down = float(np.mean(past_downs))
            if mean_down > 1.0 and down_mbps > (mean_down * 4.0):
                key = "SUDDEN_TRAFFIC_SURGE"
                if not self._should_suppress(key):
                    anomalies_to_add.append({
                        "severity": "MEDIUM",
                        "detection_method": "RULE_BASED",
                        "metric_name": "download_speed_mbps",
                        "observed_value": down_mbps,
                        "threshold_value": mean_down * 4.0,
                        "title": "Sudden Traffic Spike Beyond Rolling Baseline",
                        "explanation": f"Throughput surged to {down_mbps:.2f} Mbps, which is >400% above recent rolling average ({mean_down:.2f} Mbps).",
                        "recommendation": "Review running network services to verify if this is scheduled backup/download or unexpected traffic.",
                        "category": key
                    })

        # ==========================================
        # 2. MACHINE LEARNING: ISOLATION FOREST
        # ==========================================
        if self.is_model_trained and self.ml_model is not None:
            try:
                feature_vec = np.array([[down_mbps, up_mbps, pps, tcp_ratio, udp_ratio]])
                pred = self.ml_model.predict(feature_vec)  # -1 for anomaly, 1 for normal
                score = float(self.ml_model.decision_function(feature_vec)[0])

                if pred[0] == -1:  # Anomaly detected by unsupervised model
                    key = "ML_ISOLATION_FOREST_ANOMALY"
                    if not self._should_suppress(key):
                        severity = "HIGH" if score < -0.15 else "MEDIUM"
                        anomalies_to_add.append({
                            "severity": severity,
                            "detection_method": "ISOLATION_FOREST",
                            "metric_name": "multivariate_feature_vector",
                            "observed_value": score,
                            "threshold_value": 0.0,
                            "title": "Statistical Anomaly Detected (Isolation Forest)",
                            "explanation": (
                                f"Unsupervised ML model isolated traffic profile as an outlier (Anomaly Score: {score:.4f}). "
                                f"Observed features: Down={down_mbps:.1f} Mbps, Up={up_mbps:.1f} Mbps, Rate={pps:.0f} pps."
                            ),
                            "recommendation": "Compare protocol breakdown and active endpoints against baseline network operations profile.",
                            "category": key
                        })
            except Exception as ml_err:
                logger.error(f"Error predicting anomaly with Isolation Forest: {ml_err}")

        # ==========================================
        # PERSIST ANOMALIES & ALERTS
        # ==========================================
        for item in anomalies_to_add:
            try:
                anomaly_event = AnomalyEvent(
                    session_id=session_id,
                    is_demo=is_demo,
                    severity=item["severity"],
                    detection_method=item["detection_method"],
                    metric_name=item["metric_name"],
                    observed_value=item["observed_value"],
                    threshold_value=item["threshold_value"],
                    title=item["title"],
                    explanation=item["explanation"],
                    recommendation=item["recommendation"],
                    acknowledged=False,
                    resolved=False
                )
                db.session.add(anomaly_event)
                db.session.flush()

                # Create corresponding Alert
                alert = Alert(
                    anomaly_id=anomaly_event.id,
                    title=item["title"],
                    description=item["explanation"],
                    severity=item["severity"],
                    category=item.get("category", "ANOMALY"),
                    status="ACTIVE",
                    is_demo=is_demo
                )
                db.session.add(alert)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error saving anomaly event: {e}")

        return len(anomalies_to_add)


# Global singleton instance
anomaly_detector = AnomalyDetector()
# Pre-initialize Isolation Forest baseline so ML detection works out of the box
try:
    anomaly_detector.train_isolation_forest()
except Exception:
    pass
