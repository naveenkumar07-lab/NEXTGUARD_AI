import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "netguard-ai-secret-key-super-secure-dev")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{INSTANCE_DIR / 'netguard.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # Default Admin
    DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123")
    DEFAULT_ADMIN_EMAIL = os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@netguard.local")
    
    # Network monitoring defaults
    MONITOR_INTERVAL_SECONDS = float(os.environ.get("DEFAULT_MONITOR_INTERVAL", 2.0))
    DOWNLOAD_THRESHOLD_MBPS = float(os.environ.get("DOWNLOAD_ALERT_THRESHOLD_MBPS", 100.0))
    UPLOAD_THRESHOLD_MBPS = float(os.environ.get("UPLOAD_ALERT_THRESHOLD_MBPS", 50.0))
    PACKET_RATE_THRESHOLD_PPS = float(os.environ.get("PACKET_RATE_THRESHOLD_PPS", 5000.0))
    
    # Alert cooldown in seconds (suppress duplicate alerts within this window)
    ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", 30))
    
    # Demonstration mode
    START_IN_DEMO_MODE = os.environ.get("START_IN_DEMO_MODE", "1") == "1"
    DEFAULT_DEMO_SCENARIO = os.environ.get("DEFAULT_DEMO_SCENARIO", "NORMAL")


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key"
    START_IN_DEMO_MODE = False


class ProductionConfig(Config):
    DEBUG = False
    # In production, require strict cookie security if HTTPS is present
    SESSION_COOKIE_SECURE = os.environ.get("SECURE_COOKIE", "0") == "1"


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
