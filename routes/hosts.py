"""
Machines (hosts): one entry per MAC, or created by hand, grouping a
machine's IPv4 and IPv6 addresses. Lets the user rename a machine, bind or
unbind IPs manually and create machines the capture cannot see by MAC.
---
tags: [Hosts]
"""

from flask import Blueprint, request, jsonify

import database as db
from auth import role_required, current_user

from .common import audit_event, server_error


hosts_bp = Blueprint('hosts', __name__)


def _actor():
    return getattr(current_user, 'username', None)


def _body():
    return request.get_json(silent=True) or {}


def _not_found():
    return jsonify({"success": False, "error": "Host not found"}), 404


@hosts_bp.route('/api/hosts', methods=['GET'])
def list_hosts():
    """
    List all machines with their IP bindings.
    ---
    tags: [Hosts]
    """
    try:
        return jsonify({"success": True, "data": db.list_hosts()})
    except Exception as e:
        return server_error(e)


@hosts_bp.route('/api/hosts/<int:host_id>', methods=['GET'])
def get_host(host_id):
    """
    One machine with its IP bindings.
    ---
    tags: [Hosts]
    """
    try:
        host = db.get_host(host_id)
        if host is None:
            return _not_found()
        return jsonify({"success": True, "data": host})
    except Exception as e:
        return server_error(e)


@hosts_bp.route('/api/hosts', methods=['POST'])
@role_required('analyst')
def create_host():
    """
    Create a manual machine (no MAC), e.g. a server in another subnet.
    ---
    tags: [Hosts]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              name: {type: string}
              description: {type: string}
              device_type: {type: string}
              ips: {type: array, items: {type: string}}
    """
    try:
        data = _body()
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({"success": False, "error": "name required"}), 400
        ips = [str(ip).strip() for ip in (data.get('ips') or []) if str(ip).strip()]
        host_id = db.create_manual_host(
            name, (data.get('description') or '').strip() or None,
            data.get('device_type') or None)
        bad = []
        for ip in ips:
            try:
                db.bind_host_ip(host_id, ip, created_by=_actor())
            except ValueError:
                bad.append(ip)
        audit_event(action='create_host', target_type='host', target_id=host_id,
                    extra={'name': name, 'ips': ips, 'rejected_ips': bad})
        return jsonify({"success": True, "data": db.get_host(host_id),
                        "rejected_ips": bad}), 201
    except Exception as e:
        return server_error(e)


@hosts_bp.route('/api/hosts/<int:host_id>', methods=['PATCH'])
@role_required('analyst')
def update_host(host_id):
    """
    Rename / describe / retype a machine. name="" restores the discovered
    name; acknowledge_name_change=true clears the "name changed on the
    network" flag.
    ---
    tags: [Hosts]
    """
    try:
        data = _body()
        kwargs = {}
        for field in ('name', 'description', 'device_type'):
            if field in data:
                kwargs[field] = data[field]
        if data.get('acknowledge_name_change'):
            kwargs['acknowledge_name_change'] = True
        try:
            host = db.update_host(host_id, **kwargs)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        if host is None:
            return _not_found()
        audit_event(action='update_host', target_type='host', target_id=host_id,
                    extra={k: v for k, v in kwargs.items()})
        return jsonify({"success": True, "data": host})
    except Exception as e:
        return server_error(e)


@hosts_bp.route('/api/hosts/<int:host_id>', methods=['DELETE'])
@role_required('analyst')
def delete_host(host_id):
    """
    Delete a manual machine. Discovered machines cannot be deleted.
    ---
    tags: [Hosts]
    """
    try:
        try:
            deleted = db.delete_host(host_id)
        except ValueError:
            return jsonify({"success": False,
                            "error": "Máquinas descobertas não podem ser excluídas; "
                                     "remova os IPs em vez disso."}), 400
        if not deleted:
            return _not_found()
        audit_event(action='delete_host', target_type='host', target_id=host_id)
        return jsonify({"success": True})
    except Exception as e:
        return server_error(e)


@hosts_bp.route('/api/hosts/<int:host_id>/ips', methods=['POST'])
@role_required('analyst')
def bind_ip(host_id):
    """
    Manually bind an IP (v4 or v6) to a machine.
    ---
    tags: [Hosts]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              ip: {type: string}
    """
    try:
        ip = (_body().get('ip') or '').strip()
        if not ip:
            return jsonify({"success": False, "error": "ip required"}), 400
        try:
            ok = db.bind_host_ip(host_id, ip, created_by=_actor())
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        if not ok:
            return _not_found()
        audit_event(action='bind_host_ip', target_type='host', target_id=host_id,
                    extra={'ip': ip})
        return jsonify({"success": True, "data": db.get_host(host_id)})
    except Exception as e:
        return server_error(e)


@hosts_bp.route('/api/hosts/<int:host_id>/ips', methods=['DELETE'])
@role_required('analyst')
def unbind_ip(host_id):
    """
    Remove an IP from a machine (?ip=...). Manual bindings are deleted;
    automatic ones are marked excluded so future captures don't re-add them.
    ---
    tags: [Hosts]
    parameters:
      - in: query
        name: ip
        required: true
        schema: {type: string}
    """
    try:
        ip = (request.args.get('ip') or _body().get('ip') or '').strip()
        if not ip:
            return jsonify({"success": False, "error": "ip required"}), 400
        outcome = db.unbind_host_ip(host_id, ip)
        if outcome is None:
            return jsonify({"success": False, "error": "binding not found"}), 404
        audit_event(action='unbind_host_ip', target_type='host', target_id=host_id,
                    extra={'ip': ip, 'outcome': outcome})
        return jsonify({"success": True, "outcome": outcome,
                        "data": db.get_host(host_id)})
    except Exception as e:
        return server_error(e)
