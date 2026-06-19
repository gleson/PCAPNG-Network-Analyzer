"""
Admin endpoints: API keys for threat-intel, manual lookups, retention purge,
partition listing, audit log.
---
tags: [Admin]
"""

from flask import Blueprint, request, jsonify

import database as db
from auth import role_required

from .common import audit_event, load_settings, save_settings, server_error


admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/api/admin/api-keys', methods=['GET'])
@role_required('admin')
def get_api_keys_api():
    """
    List threat-intel services and whether each has a key configured.
    ---
    tags: [Admin]
    """
    settings = load_settings()
    from threat_intel import list_configured_services
    services = list_configured_services(settings)
    return jsonify({"success": True, "services": services})


SINGLE_KEY_SERVICES = {'abuseipdb', 'virustotal', 'shodan', 'greynoise',
                       'malwarebazaar', 'otx'}


@admin_bp.route('/api/admin/api-keys/<service>', methods=['POST'])
@role_required('admin')
def set_api_key_api(service):
    """
    Save or clear API credentials for a named service.

    Accepts either:
      * {"key": "..."}                            (legacy, single-key services)
      * {"fields": {"subfield_id": "value", ...}} (multi-field services like
        MISP/TAXII/CIRCL — each subfield_id is whitelisted via
        threat_intel.SERVICE_SUBFIELDS)
    ---
    tags: [Admin]
    """
    from threat_intel import SERVICE_SUBFIELDS
    subfields = SERVICE_SUBFIELDS.get(service)
    if subfields is None and service not in SINGLE_KEY_SERVICES:
        return jsonify({"success": False, "error": "unknown service"}), 400

    data = request.get_json(silent=True) or {}
    settings = load_settings()
    settings.setdefault('api_keys', {})

    # Build the set of writes we're about to apply: {subfield_id: value or ''}
    writes = {}
    if subfields is not None:
        # Multi-field service. Accept new-style {fields: {...}}.
        provided = data.get('fields')
        if not isinstance(provided, dict):
            return jsonify({"success": False,
                            "error": "expected {fields: {...}}"}), 400
        allowed = {f['id'] for f in subfields}
        for fid, raw in provided.items():
            if fid not in allowed:
                return jsonify({"success": False,
                                "error": f"unknown subfield {fid}"}), 400
            writes[fid] = (raw or '').strip()
    else:
        # Single-key service. Accept {key: "..."} (legacy) or {fields: {svc: "..."}}.
        if 'fields' in data and isinstance(data['fields'], dict):
            raw = data['fields'].get(service, '')
        else:
            raw = data.get('key', '')
        writes[service] = (raw or '').strip()

    cleared = []
    for fid, value in writes.items():
        if value:
            settings['api_keys'][fid] = value
        else:
            settings['api_keys'].pop(fid, None)
            cleared.append(fid)

    if save_settings(settings):
        audit_event(action='set_api_key', target_type='api_key', target_id=service,
                    extra={'fields': sorted(writes.keys()), 'cleared': cleared})
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "failed to save settings"}), 500


@admin_bp.route('/api/admin/lookup', methods=['POST'])
@role_required('analyst')
def manual_threat_lookup():
    """
    Manually look up an IP or domain against all configured threat-intel sources.
    ---
    tags: [Admin]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              indicator: {type: string}
              type: {type: string, enum: [ip, domain]}
    """
    data = request.get_json(silent=True) or {}
    indicator = (data.get('indicator') or '').strip()
    indicator_type = (data.get('type') or 'ip').lower()
    if not indicator:
        return jsonify({"success": False, "error": "indicator is required"}), 400
    if indicator_type not in ('ip', 'domain'):
        return jsonify({"success": False, "error": "type must be 'ip' or 'domain'"}), 400
    try:
        from threat_intel import manual_lookup
        settings = load_settings()
        result = manual_lookup(indicator, indicator_type, settings)
        audit_event(action='manual_lookup', target_type=indicator_type, target_id=indicator)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return server_error(e)


@admin_bp.route('/api/admin/purge', methods=['POST'])
@role_required('admin')
def admin_purge():
    """
    Delete scans and alert partitions older than retention_days.
    ---
    tags: [Admin]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              retention_days: {type: integer}
    """
    data = request.get_json(silent=True) or {}
    settings = load_settings()
    try:
        retention_days = int(data.get('retention_days') or settings.get('retention_days', 90))
    except (TypeError, ValueError):
        retention_days = 90
    try:
        deleted_scans = db.purge_old_scans(retention_days)
        dropped_parts = db.drop_old_partitions(retention_days)
        audit_event(action='retention_purge', target_type='system',
                    extra={'retention_days': retention_days,
                           'deleted_scans': deleted_scans,
                           'dropped_partitions': len(dropped_parts)})
        return jsonify({
            "success": True,
            "deleted_scans": deleted_scans,
            "dropped_partitions": dropped_parts,
            "retention_days": retention_days,
        })
    except Exception as e:
        return server_error(e)


@admin_bp.route('/api/admin/partitions', methods=['GET'])
@role_required('admin')
def list_alert_partitions_api():
    """
    List existing monthly alert partitions.
    ---
    tags: [Admin]
    """
    try:
        parts = db.list_alert_partitions()
        return jsonify({"success": True, "partitions": parts})
    except Exception as e:
        return server_error(e)


@admin_bp.route('/api/audit-log', methods=['GET'])
@role_required('analyst')
def get_audit_log():
    """
    List recent audit log entries with optional filters.
    ---
    tags: [Admin]
    parameters:
      - in: query
        name: limit
        schema: {type: integer, maximum: 1000, default: 200}
      - in: query
        name: action
        schema: {type: string}
      - in: query
        name: target_type
        schema: {type: string}
      - in: query
        name: target_id
        schema: {type: string}
      - in: query
        name: user_id
        schema: {type: string}
      - in: query
        name: since
        schema: {type: string}
    """
    try:
        limit = min(int(request.args.get('limit', 200)), 1000)
    except ValueError:
        limit = 200
    try:
        rows = db.list_audit_log(
            limit=limit,
            action=request.args.get('action') or None,
            target_type=request.args.get('target_type') or None,
            target_id=request.args.get('target_id') or None,
            user_id=request.args.get('user_id') or None,
            since=request.args.get('since') or None,
        )
        return jsonify({"success": True, "entries": rows, "count": len(rows)})
    except Exception as e:
        return server_error(e)
