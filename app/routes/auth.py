import functools
from datetime import datetime, timezone
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    current_app,
)
from app.models import User
from app.extensions import db

auth_bp = Blueprint("auth", __name__)


def login_required(view):
    """
    Decorator to protect routes requiring authentication.
    Redirects unauthenticated visitors to login page or returns 401 for API calls.
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized. Please authenticate."}), 401
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        return view(**kwargs)

    return wrapped_view


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = user.is_admin
            session.permanent = True

            user.last_login = datetime.now(timezone.utc)
            db.session.commit()

            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard.dashboard"))
        else:
            flash("Invalid credentials. Verify your username and password.", "danger")

    return render_template(
        "login.html",
        default_user=current_app.config.get("DEFAULT_ADMIN_USERNAME", "admin"),
        default_pass=current_app.config.get("DEFAULT_ADMIN_PASSWORD", "admin123"),
    )


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out safely.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/api/auth/status")
def auth_status():
    if "user_id" in session:
        return jsonify({
            "authenticated": True,
            "user_id": session["user_id"],
            "username": session["username"],
            "is_admin": session.get("is_admin", False)
        })
    return jsonify({"authenticated": False}), 401
