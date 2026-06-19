"""
User management (admin only).
---
tags: [Users]
"""

from flask import Blueprint, request, jsonify

import database as db
from auth import role_required, hash_password, current_user

from .common import audit_event


users_bp = Blueprint('users', __name__, url_prefix='/api/users')


@users_bp.route('', methods=['GET'])
@role_required('admin')
def list_users_api():
    """
    List all users.
    ---
    tags: [Users]
    responses:
      200: {description: User list}
    """
    return jsonify({"success": True, "users": db.list_users()})


@users_bp.route('', methods=['POST'])
@role_required('admin')
def create_user_api():
    """
    Create a user.
    ---
    tags: [Users]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username: {type: string}
              password: {type: string, minLength: 8}
              role: {type: string, enum: [viewer, analyst, admin]}
              enabled: {type: boolean, default: true}
              must_change_password: {type: boolean, default: true}
    responses:
      201: {description: Created}
      400: {description: Validation error}
      409: {description: Username exists}
    """
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    role = data.get('role') or 'viewer'
    if not username or len(password) < 8:
        return jsonify({"success": False, "error": "username and password (>=8 chars) required"}), 400
    if role not in db.VALID_ROLES:
        return jsonify({"success": False, "error": f"invalid role; allowed: {db.VALID_ROLES}"}), 400
    if db.get_user_by_username(username):
        return jsonify({"success": False, "error": "username already exists"}), 409
    try:
        uid = db.create_user(
            username=username,
            password_hash=hash_password(password),
            role=role,
            enabled=bool(data.get('enabled', True)),
            must_change_password=bool(data.get('must_change_password', True)),
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    audit_event(action='create_user', target_type='user', target_id=uid,
                extra={'username': username, 'role': role})
    return jsonify({"success": True, "id": uid}), 201


@users_bp.route('/<int:user_id>', methods=['DELETE'])
@role_required('admin')
def delete_user_api(user_id):
    """
    Delete a user. Cannot delete self.
    ---
    tags: [Users]
    parameters:
      - in: path
        name: user_id
        schema: {type: integer}
        required: true
    responses:
      200: {description: Deleted}
      400: {description: Cannot delete self}
      404: {description: User not found}
    """
    if getattr(current_user, 'user_id', None) == user_id:
        return jsonify({"success": False, "error": "cannot delete yourself"}), 400
    ok = db.delete_user(user_id)
    if not ok:
        return jsonify({"success": False, "error": "user not found"}), 404
    audit_event(action='delete_user', target_type='user', target_id=user_id)
    return jsonify({"success": True})


@users_bp.route('/<int:user_id>/role', methods=['POST'])
@role_required('admin')
def update_user_role_api(user_id):
    """
    Change a user's role.
    ---
    tags: [Users]
    parameters:
      - in: path
        name: user_id
        schema: {type: integer}
        required: true
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              role: {type: string, enum: [viewer, analyst, admin]}
    """
    data = request.get_json(silent=True) or {}
    role = data.get('role')
    if getattr(current_user, 'user_id', None) == user_id and role != 'admin':
        return jsonify({"success": False, "error": "cannot change own role away from admin"}), 400
    try:
        ok = db.update_user_role(user_id, role)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not ok:
        return jsonify({"success": False, "error": "user not found"}), 404
    audit_event(action='update_user_role', target_type='user', target_id=user_id,
                extra={'role': role})
    return jsonify({"success": True})


@users_bp.route('/<int:user_id>/enabled', methods=['POST'])
@role_required('admin')
def update_user_enabled_api(user_id):
    """
    Enable or disable a user.
    ---
    tags: [Users]
    parameters:
      - in: path
        name: user_id
        schema: {type: integer}
        required: true
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              enabled: {type: boolean}
    """
    data = request.get_json(silent=True) or {}
    if 'enabled' not in data:
        return jsonify({"success": False, "error": "enabled (bool) required"}), 400
    if getattr(current_user, 'user_id', None) == user_id and not data['enabled']:
        return jsonify({"success": False, "error": "cannot disable yourself"}), 400
    ok = db.update_user_enabled(user_id, bool(data['enabled']))
    if not ok:
        return jsonify({"success": False, "error": "user not found"}), 404
    audit_event(action='toggle_user', target_type='user', target_id=user_id,
                extra={'enabled': bool(data['enabled'])})
    return jsonify({"success": True})


@users_bp.route('/<int:user_id>/password', methods=['POST'])
@role_required('admin')
def admin_reset_password_api(user_id):
    """
    Admin force-reset of another user's password. Triggers must_change_password.
    ---
    tags: [Users]
    parameters:
      - in: path
        name: user_id
        schema: {type: integer}
        required: true
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              password: {type: string, minLength: 8}
    """
    data = request.get_json(silent=True) or {}
    new = data.get('password') or ''
    if len(new) < 8:
        return jsonify({"success": False, "error": "password must be >= 8 chars"}), 400
    db.update_user_password(user_id, hash_password(new), clear_must_change=False)
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET must_change_password = TRUE WHERE id = %s', (user_id,))
        conn.commit()
    audit_event(action='admin_reset_password', target_type='user', target_id=user_id)
    return jsonify({"success": True})
