"""
Authentication endpoints.
---
tags:
  - Auth
"""

import threading
import time

from flask import Blueprint, request, jsonify, session

import database as db
from auth import (
    authenticate, hash_password,
    current_user, login_user, logout_user,
    get_csrf_token,
)

from .common import audit_event


auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


# ============================================================
#  Login brute-force throttle
# ============================================================
#
# In-memory sliding-window limiter keyed by client IP. The app runs under
# Gunicorn with a single worker process (see docker-entrypoint.sh), so this
# dict is shared across every request thread. It resets on restart, which is
# acceptable for brute-force mitigation — the goal is to make online password
# guessing infeasibly slow, not to provide durable accounting.

_LOGIN_FAIL_WINDOW = 900   # seconds the sliding window covers (15 min)
_LOGIN_FAIL_MAX = 10       # failures within the window before the IP is locked
_login_attempts = {}       # ip -> list[float] failure timestamps
_login_lock = threading.Lock()


def _login_client_ip():
    """Best-effort client IP for throttling. remote_addr is used directly:
    X-Forwarded-For is client-spoofable, and trusting it would let an attacker
    rotate the header to dodge the limiter."""
    return request.remote_addr or 'unknown'


def _login_is_locked(ip):
    now = time.time()
    with _login_lock:
        hits = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_FAIL_WINDOW]
        if hits:
            _login_attempts[ip] = hits
        return len(hits) >= _LOGIN_FAIL_MAX


def _login_record_failure(ip):
    now = time.time()
    with _login_lock:
        hits = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_FAIL_WINDOW]
        hits.append(now)
        _login_attempts[ip] = hits
        # Bound memory: drop IPs whose failures have all aged out.
        if len(_login_attempts) > 4096:
            stale = [k for k, v in _login_attempts.items()
                     if not any(now - t < _LOGIN_FAIL_WINDOW for t in v)]
            for k in stale:
                _login_attempts.pop(k, None)


def _login_clear(ip):
    with _login_lock:
        _login_attempts.pop(ip, None)


@auth_bp.route('/login', methods=['POST'])
def auth_login():
    """
    Log in with username + password.
    ---
    tags: [Auth]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username: {type: string}
              password: {type: string}
    responses:
      200: {description: Logged in}
      401: {description: Invalid credentials}
      429: {description: Too many failed attempts — IP temporarily locked}
    """
    ip = _login_client_ip()
    if _login_is_locked(ip):
        return jsonify({
            "success": False,
            "error": "too many failed login attempts; try again later",
        }), 429

    data = request.get_json(silent=True) or {}
    user, err = authenticate(data.get('username'), data.get('password'))
    if err:
        _login_record_failure(ip)
        return jsonify({"success": False, "error": err}), 401
    _login_clear(ip)
    login_user(user, remember=False)
    # Make the session permanent so PERMANENT_SESSION_LIFETIME applies — gives
    # the session a bounded (sliding) lifetime instead of living forever.
    session.permanent = True
    try:
        db.touch_user_login(user.user_id)
    except Exception:
        pass
    audit_event(action='login', target_type='user', target_id=user.user_id)
    return jsonify({
        "success": True,
        "user": user.to_public_dict(),
        "csrf_token": get_csrf_token(),
    })


@auth_bp.route('/logout', methods=['POST'])
def auth_logout():
    """
    Log out the current user.
    ---
    tags: [Auth]
    responses:
      200: {description: Logged out}
    """
    if current_user.is_authenticated:
        audit_event(action='logout', target_type='user',
                    target_id=getattr(current_user, 'user_id', None))
        logout_user()
    return jsonify({"success": True})


@auth_bp.route('/me', methods=['GET'])
def auth_me():
    """
    Return the current authenticated user.
    ---
    tags: [Auth]
    responses:
      200: {description: Current user}
      401: {description: Not authenticated}
    """
    if not current_user.is_authenticated:
        return jsonify({"success": False, "error": "not authenticated"}), 401
    return jsonify({
        "success": True,
        "user": current_user.to_public_dict(),
        "csrf_token": get_csrf_token(),
    })


@auth_bp.route('/csrf-token', methods=['GET'])
def auth_csrf_token():
    """
    Return (and lazily mint) the CSRF token bound to the current session.

    The SPA fetches this on bootstrap and after login, then sends the value
    back as the X-CSRF-Token header on every mutating request.
    ---
    tags: [Auth]
    responses:
      200: {description: CSRF token}
    """
    return jsonify({"success": True, "csrf_token": get_csrf_token()})


@auth_bp.route('/password', methods=['POST'])
def auth_change_password():
    """
    Change own password. Requires current_password unless must_change_password is set.
    ---
    tags: [Auth]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              current_password: {type: string}
              new_password: {type: string, minLength: 8}
    responses:
      200: {description: Password changed}
      400: {description: Validation error}
      403: {description: Current password incorrect}
    """
    data = request.get_json(silent=True) or {}
    new = data.get('new_password') or ''
    current = data.get('current_password') or ''
    if len(new) < 8:
        return jsonify({"success": False, "error": "password must be >= 8 characters"}), 400
    if not current_user.must_change_password:
        if not current_user.check_password(current):
            return jsonify({"success": False, "error": "current password incorrect"}), 403
    db.update_user_password(current_user.user_id, hash_password(new), clear_must_change=True)
    audit_event(action='change_own_password', target_type='user',
                target_id=current_user.user_id)
    return jsonify({"success": True})
