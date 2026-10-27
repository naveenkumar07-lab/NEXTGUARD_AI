import logging
from flask import Flask, render_template, jsonify
from app.config import config_by_name
from app.extensions import db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(name)s: %(message)s"
)
logger = logging.getLogger("netguard")


def create_app(config_name="default"):
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Initialize extensions
    db.init_app(app)

    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.monitoring import monitoring_bp
    from app.routes.analytics import analytics_bp
    from app.routes.health import health_bp
    from app.routes.connections import connections_bp
    from app.routes.alerts import alerts_bp
    from app.routes.reports import reports_bp
    from app.routes.settings import settings_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(connections_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(api_bp)

    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("500.html"), 500

    # Global Template Context
    @app.context_processor
    def inject_global_vars():
        from app.services.network_collector import collector
        from app.services.demo_generator import demo_generator
        from app.models import Alert

        active_alerts = 0
        try:
            active_alerts = Alert.query.filter_by(status="ACTIVE").count()
        except Exception:
            pass

        return {
            "current_year": 2026,
            "collector_active": collector.is_active(),
            "is_demo_mode": collector.is_demo_mode,
            "active_interface": collector.active_interface,
            "current_scenario": demo_generator.current_scenario,
            "active_alerts_badge": active_alerts,
        }

    # First-run initialization within application context
    with app.app_context():
        db.create_all()

        # Create default admin user if not already existing
        from app.models import User
        default_user = app.config.get("DEFAULT_ADMIN_USERNAME", "admin")
        default_pass = app.config.get("DEFAULT_ADMIN_PASSWORD", "admin123")
        default_email = app.config.get("DEFAULT_ADMIN_EMAIL", "admin@netguard.local")

        admin = User.query.filter_by(username=default_user).first()
        if not admin:
            admin = User(
                username=default_user,
                email=default_email,
                is_admin=True
            )
            admin.set_password(default_pass)
            db.session.add(admin)
            db.session.commit()
            logger.info(f"Default administrator '{default_user}' created successfully.")

        # Seed initial demo baseline if database is empty and demo mode configured
        from app.models import NetworkMetric
        if NetworkMetric.query.count() == 0 and app.config.get("START_IN_DEMO_MODE"):
            from app.services.network_collector import collector
            logger.info("Initializing background collector in Demonstration Mode...")
            collector.start_monitoring(
                app=app,
                is_demo=True,
                interval=app.config.get("MONITOR_INTERVAL_SECONDS", 2.0)
            )

    return app
