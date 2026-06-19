"""
Authentication and RBAC.

Stack:
  - werkzeug.security for password hashing (already a Flask dep — no extra deps)
  - Flask-Login for session management
  - PostgreSQL `users` table (managed by database.py)

Roles, in order of privilege:
  - viewer:  read-only access (GET endpoints + login/logout)
  - analyst: viewer + state-changing operations (uploads, triage, suppression,
             webhook CRUD, settings update, exports, replays)
  - admin:   analyst + user management

Helpers:
  - `init_auth(app)` wires Flask-Login into the Flask app, configures the
    session secret, and bootstraps a default admin if the users table is empty.
  - `role_required('admin'|'analyst')` decorates a route to gate access.
  - `current_role_at_least(role)` is the predicate version (use in templates
    or programmatic checks).

Public endpoints (login/logout/me) are registered in app.py so they live
alongside the rest of the API surface.
"""
import hmac
import os
import secrets
import warnings
from datetime import timedelta
from functools import wraps

from flask import g, jsonify, request, session
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_user,
    logout_user,
    login_required,
)

import database as db


# ============================================================
#  User wrapper for Flask-Login
# ============================================================

class User(UserMixin):
    """Adapts a row from db.users into Flask-Login's expected shape."""

    def __init__(self, row):
        self.id = str(row["id"])      # Flask-Login expects str id
        self.user_id = row["id"]      # Convenience int form
        self.username = row["username"]
        self.role = row["role"]
        self.enabled = bool(row["enabled"])
        self.must_change_password = bool(row.get("must_change_password", False))
        self.password_hash = row.get("password_hash")

    @property
    def is_active(self):
        return self.enabled

    def check_password(self, plain):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, plain)

    def to_public_dict(self):
        return {
            "id": self.user_id,
            "username": self.username,
            "role": self.role,
            "enabled": self.enabled,
            "must_change_password": self.must_change_password,
        }


# ============================================================
#  Flask-Login wiring
# ============================================================

login_manager = LoginManager()
login_manager.login_view = "login_page"   # set in app.py

# Precomputed hash compared against when a username does not exist, so a
# missing account costs the same wall-clock time as a wrong password. Without
# it, the fast "no such user" path leaks account existence via response timing.
_DUMMY_PASSWORD_HASH = generate_password_hash("timing-equalisation-dummy")

# Paths reachable without authentication. The SPA shell ("/") is public
# because it's a static HTML wrapper — actual data is fetched via API
# calls that the gate below challenges.
PUBLIC_PATH_PREFIXES = (
    "/api/auth/login",
    "/api/auth/me",          # returns 401 silently when not logged in
    "/api/auth/csrf-token",  # bootstraps the SPA's CSRF header
    "/login",                # legacy alias if a UI route is added
    "/static/",
    "/favicon.ico",
)
PUBLIC_PATH_EXACT = {
    "/",
}


# ============================================================
#  CSRF protection
# ============================================================
#
# Session-bound token, exposed via /api/auth/csrf-token and consumed via the
# X-CSRF-Token header. Login is intentionally exempt: the token is bound to
# the session, and the login request is what creates the session in the
# first place.
#
# SESSION_COOKIE_SAMESITE=Lax already blocks cross-site POSTs via forms, but
# this header check closes the remaining gaps (same-site sub-domain takeovers,
# bypasses via legacy browsers, and developer tools/CORS misconfigurations).

CSRF_SESSION_KEY = "_csrf_token"
CSRF_HEADER = "X-CSRF-Token"
CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Endpoints intentionally exempt from CSRF: they cannot be authenticated
# (login creates the session) and there is no harmful side-effect a third
# party could trigger here.
CSRF_EXEMPT_PATHS = ("/api/auth/login",)


def get_csrf_token():
    """Return the per-session CSRF token, lazily minting one on first use."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _require_csrf_for_mutating_requests():
    """Reject mutating requests that omit or fail the CSRF check."""
    if request.method not in CSRF_PROTECTED_METHODS:
        return None
    path = request.path or ""
    if any(path == p or path.startswith(p + "/") for p in CSRF_EXEMPT_PATHS):
        return None
    expected = session.get(CSRF_SESSION_KEY)
    provided = request.headers.get(CSRF_HEADER, "")
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        return jsonify({"success": False, "error": "CSRF token missing or invalid"}), 403
    return None


@login_manager.user_loader
def _load_user(user_id):
    try:
        row = db.get_user_by_id(int(user_id))
    except (TypeError, ValueError):
        return None
    if not row or not row.get("enabled"):
        return None
    return User(row)


@login_manager.unauthorized_handler
def _unauthorized():
    # Always return a JSON 401 — the SPA will render the login page itself
    # when it sees this.
    return jsonify({"success": False, "error": "authentication required"}), 401


# ============================================================
#  Decorators
# ============================================================

def role_required(min_role):
    """
    Allow only users whose role is at least `min_role`. Authentication is
    already enforced by the before_request hook; this decorator only adds
    the role check.
    """
    if min_role not in db.ROLE_RANK:
        raise ValueError(f"unknown role {min_role!r}")

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                # Defensive: shouldn't be reachable thanks to before_request,
                # but a stray unprotected route would land here.
                return jsonify({"success": False, "error": "authentication required"}), 401
            if db.ROLE_RANK.get(current_user.role, -1) < db.ROLE_RANK[min_role]:
                return jsonify({
                    "success": False,
                    "error": f"requires role >= {min_role}",
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def current_role_at_least(role):
    if not current_user.is_authenticated:
        return False
    return db.ROLE_RANK.get(current_user.role, -1) >= db.ROLE_RANK.get(role, 99)


# ============================================================
#  before_request gate
# ============================================================

def _require_auth_for_protected_paths():
    """
    Block every request that isn't on the public list unless the user is
    authenticated. This is the safety net so a forgotten decorator on an
    individual route can't expose data.
    """
    path = request.path or ""
    if path in PUBLIC_PATH_EXACT:
        return None
    if any(path.startswith(p) for p in PUBLIC_PATH_PREFIXES):
        return None
    if current_user.is_authenticated:
        return None
    return jsonify({"success": False, "error": "authentication required"}), 401


# ============================================================
#  Bootstrap & init
# ============================================================

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD_ENV = "PCAP_DEFAULT_ADMIN_PASSWORD"


def init_auth(app):
    """
    Wire Flask-Login into the app. Call from app.py after app = Flask(__name__).
    """
    secret = os.environ.get("FLASK_SECRET_KEY")
    if not secret:
        # Generate-on-startup keeps dev sessions consistent within a process
        # but invalidates them on restart — users must set the env var in
        # production for stable sessions.
        secret = secrets.token_hex(32)
        warnings.warn(
            "FLASK_SECRET_KEY not set — sessions will not survive restarts. "
            "Set this env var in production."
        )
    app.config["SECRET_KEY"] = secret
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    # SESSION_COOKIE_SECURE must be ON whenever the app is reachable over
    # HTTPS, so the session cookie is never transmitted in cleartext. It is
    # opt-in via env because the bundled docker-compose serves plain HTTP on
    # :5000 — a browser withholds a Secure cookie there and login would fail.
    # Set SESSION_COOKIE_SECURE=1 once a TLS-terminating proxy is in front.
    secure_cookie = os.environ.get("SESSION_COOKIE_SECURE", "").lower() in (
        "1", "true", "yes", "on")
    app.config.setdefault("SESSION_COOKIE_SECURE", secure_cookie)

    # Absolute/idle session timeout. Sessions are marked permanent on login
    # (see routes/auth.py), so this lifetime applies; SESSION_REFRESH_EACH_
    # REQUEST (Flask default True) turns it into a sliding idle timeout.
    try:
        lifetime_hours = float(os.environ.get("SESSION_LIFETIME_HOURS", "12"))
    except ValueError:
        lifetime_hours = 12.0
    app.config.setdefault("PERMANENT_SESSION_LIFETIME",
                          timedelta(hours=lifetime_hours))

    login_manager.init_app(app)
    app.before_request(_require_auth_for_protected_paths)
    # CSRF check runs after auth so unauthenticated callers still get a 401
    # (not a confusing "CSRF token missing") on protected paths.
    app.before_request(_require_csrf_for_mutating_requests)

    _bootstrap_admin_if_empty()


def _bootstrap_admin_if_empty():
    try:
        if db.count_users() > 0:
            return
    except Exception as e:
        # If the users table doesn't exist yet (legacy dev DB), the schema
        # init in database.py creates it on import. If we still can't count,
        # leave bootstrap to a later restart.
        print(f"[auth] could not check user count, skipping bootstrap: {e}")
        return

    password = os.environ.get(DEFAULT_ADMIN_PASSWORD_ENV)
    must_change = False
    if not password:
        password = secrets.token_urlsafe(12)
        must_change = True
        print(
            "\n========================================================\n"
            "[auth] No users in database. Bootstrapping default admin.\n"
            f"       username: {DEFAULT_ADMIN_USERNAME}\n"
            f"       password: {password}\n"
            "       (must be changed on first login)\n"
            "       To set explicitly, restart with "
            f"{DEFAULT_ADMIN_PASSWORD_ENV}=<password>\n"
            "========================================================\n",
            flush=True,
        )

    try:
        db.create_user(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=generate_password_hash(password),
            role="admin",
            enabled=True,
            must_change_password=must_change,
        )
    except Exception as e:
        print(f"[auth] failed to bootstrap admin: {e}")


# ============================================================
#  Helpers used by app.py login routes
# ============================================================

def authenticate(username, password):
    """
    Verify credentials. Returns (User, error_string|None). On success,
    error is None. On failure, User is None and error is a short reason.
    """
    if not username or not password:
        return None, "username and password required"
    row = db.get_user_by_username(username)
    if not row:
        # Spend the same work as a real password check so a missing username
        # cannot be told apart from a wrong password by response timing.
        check_password_hash(_DUMMY_PASSWORD_HASH, password)
        return None, "invalid credentials"
    user = User(row)
    # Always run the hash check (even for disabled accounts) to keep timing
    # flat, and return one generic message so neither branch leaks whether
    # the account exists or is merely disabled.
    password_ok = user.check_password(password)
    if not user.enabled or not password_ok:
        return None, "invalid credentials"
    return user, None


def hash_password(plain):
    return generate_password_hash(plain)


__all__ = [
    "User",
    "login_manager",
    "init_auth",
    "role_required",
    "current_role_at_least",
    "authenticate",
    "hash_password",
    "current_user",
    "login_user",
    "logout_user",
    "get_csrf_token",
    "CSRF_HEADER",
]
