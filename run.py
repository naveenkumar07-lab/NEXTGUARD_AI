import os
from app import create_app

env = os.environ.get("FLASK_ENV", "development")
app = create_app("development" if env == "development" else "production")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    
    print("=" * 65)
    print("  NETGUARD AI — NETWORK TRAFFIC MONITORING & ANOMALY DETECTION")
    print(f"  Running on: http://{host}:{port}")
    print("  Default Login: admin / admin123")
    print("=" * 65)
    
    app.run(host=host, port=port, debug=debug)
