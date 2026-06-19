"""
PCAP Network Analyzer - Flask Web Application

Wiring layer only:
  - creates the Flask app
  - configures auth, audit hook, Swagger UI
  - registers blueprints under routes/

All endpoint code lives in routes/. Shared helpers and state live in
routes/common.py.
"""

import os

from flask import Flask, request, g, jsonify
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

import database as db
from auth import init_auth, current_user
from routes import register_all
from routes import common
from routes.common import (
    AUDIT_MUTATING_METHODS, AUDIT_PATH_BLOCKLIST_PREFIXES, CELERY_AVAILABLE,
)
from routes.vite import vite_assets


def create_app():
    app = Flask(__name__)

    # ---- Reverse-proxy awareness -----------------------------------------
    # X-Forwarded-* headers are client-spoofable; honour them only when a
    # known number of trusted proxies sit in front. Default 0 = trust nothing,
    # so request.remote_addr is always the real socket peer. Set
    # TRUSTED_PROXY_COUNT to the proxy hop count when deploying behind one.
    _proxy_count = int(os.environ.get('TRUSTED_PROXY_COUNT', '0') or '0')
    if _proxy_count > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_count,
                                x_proto=_proxy_count, x_host=_proxy_count)

    # ---- Config -----------------------------------------------------------
    app.config['UPLOAD_FOLDER'] = common.UPLOAD_FOLDER
    # Hard cap on any request body. Uploads legitimately need to be large
    # (multi-GB PCAPs) so the cap is generous; every non-upload endpoint is
    # held to a much smaller limit by _limit_request_body() below. `None`
    # (unlimited) would let a single request exhaust the container's memory.
    app.config['MAX_CONTENT_LENGTH'] = int(
        os.environ.get('MAX_UPLOAD_BYTES', 10 * 1024 ** 3))  # 10 GiB default
    app.config['ALLOWED_EXTENSIONS'] = common.ALLOWED_EXTENSIONS

    # ---- Auth + RBAC ------------------------------------------------------
    # init_auth wires Flask-Login, sets the session secret, and bootstraps a
    # default admin if the users table is empty.
    init_auth(app)

    # ---- Request body size guard -----------------------------------------
    # MAX_CONTENT_LENGTH (above) bounds uploads; this keeps every *other*
    # endpoint to a small body so one request cannot balloon memory through
    # request.get_json() buffering. Only file-upload routes may exceed it.
    LARGE_BODY_PREFIXES = ('/api/upload', '/api/user-rules/import')
    SMALL_BODY_LIMIT = 4 * 1024 * 1024  # 4 MiB

    @app.before_request
    def _limit_request_body():
        length = request.content_length
        if length is None or length <= SMALL_BODY_LIMIT:
            return None
        path = request.path or ''
        if any(path.startswith(p) for p in LARGE_BODY_PREFIXES):
            return None
        return jsonify({"success": False,
                        "error": "request body too large"}), 413

    # ---- Swagger / OpenAPI ------------------------------------------------
    # Flasgger turns the docstrings in routes/* into an interactive Swagger UI
    # at /apidocs (raw spec at /apispec_1.json). Set DISABLE_SWAGGER=1 to leave
    # the API surface undocumented (endpoints still require auth either way).
    _swagger_off = os.environ.get('DISABLE_SWAGGER', '').lower() in (
        '1', 'true', 'yes', 'on')
    try:
        if _swagger_off:
            raise RuntimeError('swagger disabled')
        from flasgger import Swagger
        Swagger(app, template={
            "openapi": "3.0.2",
            "info": {
                "title": "PCAP Network Analyzer API",
                "description": "REST API for PCAP/PCAPNG analysis, alert triage, "
                               "threat intel, rules, users and admin operations.",
                "version": "3.0",
            },
            "tags": [
                {"name": "Auth",   "description": "Login / logout / password change"},
                {"name": "Users",  "description": "User management (admin)"},
                {"name": "Scans",  "description": "Upload, status, results, packets, replay, reports"},
                {"name": "Alerts", "description": "Alert triage, suppression, FP signatures, webhooks"},
                {"name": "Rules",  "description": "User-defined detection rules"},
                {"name": "Admin",  "description": "API keys, manual lookup, retention, audit log"},
                {"name": "Config", "description": "Settings, IP labels, trusted ranges"},
            ],
        })
    except RuntimeError:
        print("[app] Swagger UI disabled via DISABLE_SWAGGER.")
    except ImportError:
        # Swagger is optional: missing flasgger should not break the app.
        print("[app] flasgger not installed — Swagger UI disabled. "
              "Install with: pip install flasgger")

    # ---- Audit log hook ---------------------------------------------------
    @app.after_request
    def _audit_after_request(response):
        try:
            if request.method not in AUDIT_MUTATING_METHODS:
                return response
            path = request.path or ''
            if any(path.startswith(p) for p in AUDIT_PATH_BLOCKLIST_PREFIXES):
                return response
            # remote_addr is the real peer, or proxy-corrected by ProxyFix
            # when TRUSTED_PROXY_COUNT is set. X-Forwarded-For is never read
            # directly — it is client-spoofable and would forge the audit IP.
            actor_ip = request.remote_addr
            user_id = None
            if current_user.is_authenticated:
                user_id = getattr(current_user, 'username', None) or str(getattr(current_user, 'user_id', ''))
            db.write_audit(
                method=request.method,
                path=path,
                status_code=response.status_code,
                action=getattr(g, 'audit_action', None),
                target_type=getattr(g, 'audit_target_type', None),
                target_id=getattr(g, 'audit_target_id', None),
                user_id=user_id,
                actor_ip=actor_ip,
                extra=getattr(g, 'audit_extra', None),
            )
        except Exception as e:
            print(f"[audit] hook failed: {e}")
        return response

    # ---- Security headers -------------------------------------------------
    # Applied to every response. The CSP keeps 'unsafe-inline' for scripts
    # because templates/index.html relies on inline on*-handlers; it still
    # blocks external script/style/object loads, framing and base-tag hijack.
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Content-Security-Policy', csp)
        # HSTS is only meaningful — and only emitted — when served over HTTPS.
        if app.config.get('SESSION_COOKIE_SECURE'):
            response.headers.setdefault(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains')
        return response

    # ---- Uncaught exception handler --------------------------------------
    # Safety net for code that raises outside a route's own try/except: log
    # the detail server-side, return an opaque 500. HTTP errors (401/403/404/
    # 413/...) keep their intended status and body.
    @app.errorhandler(Exception)
    def _handle_uncaught(e):
        if isinstance(e, HTTPException):
            return e
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": "internal server error"}), 500

    # ---- Frontend bundle (Vite) -------------------------------------------
    # Inject hashed asset tags into templates via {{ vite_assets() }}.
    app.jinja_env.globals['vite_assets'] = vite_assets

    # ---- Blueprints -------------------------------------------------------
    register_all(app)

    return app


app = create_app()


if __name__ == '__main__':
    # Running `python app.py` directly starts the Flask dev server — for LOCAL
    # DEVELOPMENT ONLY. Production runs under Gunicorn (see docker-entrypoint.sh).
    #
    # Debug mode is OFF unless FLASK_DEBUG is explicitly set: debug=True exposes
    # the Werkzeug interactive debugger, which allows arbitrary code execution
    # on any unhandled exception — never acceptable on a network-bound app.
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('data', exist_ok=True)

    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes', 'on')

    print("=" * 60)
    print("PCAP Network Analyzer v3.0 - Starting (dev server)...")
    print("=" * 60)
    print("Server running at: http://localhost:5000")
    print("Swagger UI:        http://localhost:5000/apidocs")
    print(f"Database: {os.environ.get('DATABASE_URL', 'PostgreSQL')}")
    print(f"Celery:   {'Enabled' if CELERY_AVAILABLE else 'Disabled (using threading)'}")
    print(f"Debug:    {debug}")
    print("=" * 60)

    app.run(debug=debug, host='0.0.0.0', port=5000, threaded=True)
