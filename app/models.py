from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class BaseModel(db.Model):
    __abstract__ = True

    def __init__(self, **kwargs):
        super().__init__()
        for key, value in kwargs.items():
            setattr(self, key, value)


class User(BaseModel):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utc_now)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class MonitoringSession(BaseModel):
    __tablename__ = "monitoring_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    interface_name = db.Column(db.String(100), nullable=False)
    is_demo = db.Column(db.Boolean, default=False)
    started_at = db.Column(db.DateTime, default=utc_now, index=True)
    stopped_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    total_bytes_recv = db.Column(db.BigInteger, default=0)
    total_bytes_sent = db.Column(db.BigInteger, default=0)
    total_packets = db.Column(db.BigInteger, default=0)

    metrics = db.relationship("NetworkMetric", backref="session", lazy="dynamic", cascade="all, delete-orphan")
    anomalies = db.relationship("AnomalyEvent", backref="session", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "session_uuid": self.session_uuid,
            "interface_name": self.interface_name,
            "is_demo": self.is_demo,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
            "is_active": self.is_active,
            "total_bytes_recv": self.total_bytes_recv,
            "total_bytes_sent": self.total_bytes_sent,
            "total_packets": self.total_packets,
        }


class NetworkMetric(BaseModel):
    __tablename__ = "network_metrics"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("monitoring_sessions.id"), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    interface_name = db.Column(db.String(100), nullable=False)
    is_demo = db.Column(db.Boolean, default=False)
    
    # Raw counters
    bytes_recv = db.Column(db.BigInteger, default=0)
    bytes_sent = db.Column(db.BigInteger, default=0)
    packets_recv = db.Column(db.BigInteger, default=0)
    packets_sent = db.Column(db.BigInteger, default=0)

    # Calculated rates per second
    download_speed_bps = db.Column(db.Float, default=0.0)  # bytes per sec
    upload_speed_bps = db.Column(db.Float, default=0.0)    # bytes per sec
    download_speed_mbps = db.Column(db.Float, default=0.0) # Megabits per sec
    upload_speed_mbps = db.Column(db.Float, default=0.0)   # Megabits per sec
    packet_rate_pps = db.Column(db.Float, default=0.0)     # packets per sec

    # Protocol distribution breakdown (from Scapy or synthetic packet analyzer)
    tcp_packets = db.Column(db.Integer, default=0)
    udp_packets = db.Column(db.Integer, default=0)
    icmp_packets = db.Column(db.Integer, default=0)
    dns_packets = db.Column(db.Integer, default=0)
    http_packets = db.Column(db.Integer, default=0)
    https_packets = db.Column(db.Integer, default=0)
    other_packets = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "interface_name": self.interface_name,
            "is_demo": self.is_demo,
            "bytes_recv": self.bytes_recv,
            "bytes_sent": self.bytes_sent,
            "packets_recv": self.packets_recv,
            "packets_sent": self.packets_sent,
            "download_speed_bps": self.download_speed_bps,
            "upload_speed_bps": self.upload_speed_bps,
            "download_speed_mbps": round(self.download_speed_mbps, 3),
            "upload_speed_mbps": round(self.upload_speed_mbps, 3),
            "packet_rate_pps": round(self.packet_rate_pps, 1),
            "protocols": {
                "tcp": self.tcp_packets,
                "udp": self.udp_packets,
                "icmp": self.icmp_packets,
                "dns": self.dns_packets,
                "http": self.http_packets,
                "https": self.https_packets,
                "other": self.other_packets,
            },
        }


class AnomalyEvent(BaseModel):
    __tablename__ = "anomaly_events"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("monitoring_sessions.id"), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    is_demo = db.Column(db.Boolean, default=False)
    severity = db.Column(db.String(20), default="MEDIUM")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    detection_method = db.Column(db.String(30), default="RULE_BASED")  # RULE_BASED, ISOLATION_FOREST
    metric_name = db.Column(db.String(80), nullable=False)
    observed_value = db.Column(db.Float, default=0.0)
    threshold_value = db.Column(db.Float, nullable=True)
    title = db.Column(db.String(200), nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

    alert = db.relationship("Alert", backref="anomaly_event", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "is_demo": self.is_demo,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "metric_name": self.metric_name,
            "observed_value": round(self.observed_value, 2) if self.observed_value is not None else 0.0,
            "threshold_value": round(self.threshold_value, 2) if self.threshold_value is not None else None,
            "title": self.title,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class Alert(BaseModel):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    anomaly_id = db.Column(db.Integer, db.ForeignKey("anomaly_events.id"), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default="MEDIUM", index=True)
    category = db.Column(db.String(50), default="TRAFFIC_SPIKE")
    status = db.Column(db.String(20), default="ACTIVE", index=True)  # ACTIVE, ACKNOWLEDGED, RESOLVED
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String(80), nullable=True)
    is_demo = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "anomaly_id": self.anomaly_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "status": self.status,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "is_demo": self.is_demo,
        }


class NetworkHealthLog(BaseModel):
    __tablename__ = "network_health_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    target_host = db.Column(db.String(120), default="8.8.8.8")
    health_score = db.Column(db.Float, default=100.0)  # 0 to 100
    latency_ms = db.Column(db.Float, nullable=True)
    jitter_ms = db.Column(db.Float, nullable=True)
    packet_loss_pct = db.Column(db.Float, default=0.0)
    status_label = db.Column(db.String(30), default="EXCELLENT")  # EXCELLENT, GOOD, FAIR, POOR, CRITICAL
    bottlenecks = db.Column(db.Text, default="")
    recommendations = db.Column(db.Text, default="")
    is_demo = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "target_host": self.target_host,
            "health_score": round(self.health_score, 1),
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "jitter_ms": round(self.jitter_ms, 2) if self.jitter_ms is not None else None,
            "packet_loss_pct": round(self.packet_loss_pct, 1),
            "status_label": self.status_label,
            "bottlenecks": self.bottlenecks,
            "recommendations": self.recommendations,
            "is_demo": self.is_demo,
        }


class NetworkConnectionRecord(BaseModel):
    __tablename__ = "network_connections"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    transport_proto = db.Column(db.String(10), default="TCP")
    local_address = db.Column(db.String(100), nullable=False)
    local_port = db.Column(db.Integer, nullable=True)
    remote_address = db.Column(db.String(100), default="N/A")
    remote_port = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(30), default="ESTABLISHED")
    pid = db.Column(db.Integer, nullable=True)
    process_name = db.Column(db.String(100), default="Unknown")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "transport_proto": self.transport_proto,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "status": self.status,
            "pid": self.pid,
            "process_name": self.process_name,
        }


class AppSetting(BaseModel):
    __tablename__ = "app_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), default="")
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

    def to_dict(self):
        return {
            "key": self.key,
            "value": self.value,
            "description": self.description,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
