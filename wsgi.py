import os
from app import create_app

env = os.environ.get("FLASK_ENV", "production")
app = create_app(env if env in ["development", "production", "testing"] else "production")

if __name__ == "__main__":
    from waitress import serve
    port = int(os.environ.get("PORT", 5000))
    print(f"Serving NetGuard AI with Waitress on http://0.0.0.0:{port}...")
    serve(app, host="0.0.0.0", port=port)
