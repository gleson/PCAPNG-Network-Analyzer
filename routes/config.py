"""
Configuration endpoints: app settings, IP labels (names/descriptions),
trusted CIDR ranges, device types, IP evolution history.
---
tags: [Config]
"""

import json
from datetime import datetime

from flask import Blueprint, request, jsonify, Response

import database as db
from auth import role_required

from .common import audit_event, load_settings, save_settings, server_error


config_bp = Blueprint('config', __name__)


# ============================================================
# Settings — secret redaction
# ============================================================
#
# settings.json holds secret material: threat-intel `api_keys` and the SMTP
# `password`. The settings GET endpoint is readable by any authenticated user
# (including `viewer`), so the raw file must never be returned over HTTP.
#
# The frontend round-trips settings (GET → edit → POST the whole object), so
# redaction alone would wipe the secrets on the next save. _restore_secrets()
# merges the stored values back in whenever the payload omits them or still
# carries the redaction placeholder.

_SECRET_REDACTED = '__redacted__'


def _redact_settings(settings):
    """Return a copy of *settings* safe to send to a browser.

    `api_keys` is dropped entirely (managed via /api/admin/api-keys); the SMTP
    password is masked so host/port/user stay visible without leaking the key.
    """
    redacted = dict(settings or {})
    redacted.pop('api_keys', None)
    smtp = redacted.get('smtp')
    if isinstance(smtp, dict) and smtp.get('password'):
        smtp = dict(smtp)
        smtp['password'] = _SECRET_REDACTED
        redacted['smtp'] = smtp
    return redacted


def _restore_secrets(new_settings, existing):
    """Merge secrets from the on-disk *existing* settings into *new_settings*
    so a save that round-tripped through the redacted GET cannot erase them.
    """
    existing = existing or {}
    # api_keys is never exposed here — always keep the stored copy. To change
    # keys, callers must use the dedicated /api/admin/api-keys endpoint.
    if 'api_keys' in existing:
        new_settings['api_keys'] = existing['api_keys']
    # smtp.password: restore when missing or still the redaction placeholder;
    # a genuine new value (anything else) is written through unchanged.
    new_smtp = new_settings.get('smtp')
    if isinstance(new_smtp, dict):
        old_pw = (existing.get('smtp') or {}).get('password')
        if old_pw and new_smtp.get('password') in (None, '', _SECRET_REDACTED):
            new_smtp['password'] = old_pw
    return new_settings


# ============================================================
# Settings
# ============================================================

@config_bp.route('/api/settings', methods=['GET'])
def get_settings():
    """
    Return current app settings (secrets redacted).
    ---
    tags: [Config]
    """
    settings = load_settings()
    return jsonify({"success": True, "data": _redact_settings(settings)})


@config_bp.route('/api/settings', methods=['POST'])
@role_required('analyst')
def update_settings():
    """
    Replace app settings (full JSON overwrite). Secret fields omitted or sent
    with the redaction placeholder are preserved from the stored settings.
    ---
    tags: [Config]
    requestBody:
      required: true
      content:
        application/json:
          schema: {type: object}
    """
    try:
        new_settings = request.json
        if not new_settings:
            return jsonify({"success": False, "error": "No settings provided"}), 400
        if not isinstance(new_settings, dict):
            return jsonify({"success": False, "error": "Settings must be a JSON object"}), 400

        new_settings = _restore_secrets(new_settings, load_settings())

        if save_settings(new_settings):
            audit_event(action='update_settings', target_type='settings')
            return jsonify({"success": True, "message": "Settings saved successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to save settings"}), 500
    except Exception as e:
        return server_error(e)


# ============================================================
# IP descriptions / names / evolution
# ============================================================

@config_bp.route('/api/ip-description', methods=['POST'])
@role_required('analyst')
def add_ip_description():
    """
    Legacy: add an IP description into settings.json.
    ---
    tags: [Config]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              ip: {type: string}
              description: {type: string}
    """
    try:
        data = request.json
        ip = data.get('ip')
        description = data.get('description')

        if not ip or not description:
            return jsonify({"success": False, "error": "IP and description required"}), 400

        settings = load_settings()
        if 'ip_descriptions' not in settings:
            settings['ip_descriptions'] = {}
        settings['ip_descriptions'][ip] = description

        if save_settings(settings):
            return jsonify({"success": True, "message": "IP description saved"})
        else:
            return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/ip-names', methods=['GET'])
def get_ip_names():
    """
    Return all IP labels.
    ---
    tags: [Config]
    """
    try:
        ip_names = db.get_all_ip_names()
        return jsonify({"success": True, "data": ip_names})
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/ip-names', methods=['POST'])
@role_required('analyst')
def set_ip_name():
    """
    Set or update the label/description/device_type for an IP.
    ---
    tags: [Config]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              ip: {type: string}
              name: {type: string}
              description: {type: string}
              device_type: {type: string}
    """
    try:
        data = request.json
        ip = data.get('ip')
        name = data.get('name')
        description = data.get('description', '')
        device_type = data.get('device_type') or None

        if not ip or not name:
            return jsonify({"success": False, "error": "IP and name required"}), 400

        db.set_ip_name(ip, name, description, device_type)
        return jsonify({"success": True, "message": "IP name saved"})
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/ip-names/export', methods=['GET'])
@role_required('analyst')
def export_ip_names():
    """
    Download all IP labels as a JSON backup.
    ---
    tags: [Config]
    """
    try:
        ip_names = db.get_all_ip_names()
        payload = {
            "version": 1,
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "count": len(ip_names),
            "ip_names": ip_names,
        }
        body = json.dumps(payload, ensure_ascii=False, indent=2)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        audit_event(action='export_ip_names', target_type='ip_names',
                    extra={'count': len(ip_names)})
        return Response(
            body,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename="ip_names_{stamp}.json"'
            }
        )
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/ip-names/import', methods=['POST'])
@role_required('analyst')
def import_ip_names():
    """
    Bulk import/update IP labels from a JSON document.
    ---
    tags: [Config]
    parameters:
      - in: query
        name: mode
        schema: {type: string, enum: [overwrite, skip], default: overwrite}
    requestBody:
      required: true
      content:
        application/json:
          schema: {type: object}
    """
    try:
        mode = (request.args.get('mode') or 'overwrite').lower()
        payload = request.json
        if payload is None:
            return jsonify({"success": False, "error": "JSON inválido"}), 400

        items = {}
        if isinstance(payload, dict) and isinstance(payload.get('ip_names'), dict):
            raw = payload['ip_names']
        elif isinstance(payload, dict):
            raw = payload
        elif isinstance(payload, list):
            raw = {}
            for entry in payload:
                if isinstance(entry, dict) and entry.get('ip'):
                    raw[entry['ip']] = entry
        else:
            return jsonify({"success": False, "error": "Formato não reconhecido"}), 400

        for ip, info in raw.items():
            if not isinstance(info, dict):
                continue
            name = (info.get('name') or '').strip()
            if not ip or not name:
                continue
            items[ip] = {
                'name': name,
                'description': info.get('description') or '',
                'device_type': info.get('device_type') or None,
            }

        if not items:
            return jsonify({"success": False, "error": "Nenhuma entrada válida no arquivo"}), 400

        existing = db.get_all_ip_names() if mode == 'skip' else {}

        imported = 0
        skipped = 0
        for ip, info in items.items():
            if mode == 'skip' and ip in existing:
                skipped += 1
                continue
            db.set_ip_name(ip, info['name'], info['description'], info['device_type'])
            imported += 1

        audit_event(action='import_ip_names', target_type='ip_names',
                    extra={'imported': imported, 'skipped': skipped, 'mode': mode})
        return jsonify({
            "success": True,
            "imported": imported,
            "skipped": skipped,
            "total": len(items),
            "mode": mode,
        })
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/device-types', methods=['GET'])
def get_device_types():
    """
    Allowed device-type values for the IP labels.
    ---
    tags: [Config]
    """
    return jsonify({"success": True, "data": list(db.DEVICE_TYPES), "default": db.DEVICE_TYPE_DEFAULT})


@config_bp.route('/api/ip-names/<ip>', methods=['DELETE'])
@role_required('analyst')
def delete_ip_name(ip):
    """
    Remove the label for an IP. URL-encode dots as dashes.
    ---
    tags: [Config]
    parameters:
      - in: path
        name: ip
        schema: {type: string}
        required: true
    """
    try:
        ip = ip.replace('-', '.')
        if db.delete_ip_name(ip):
            return jsonify({"success": True, "message": "IP name deleted"})
        else:
            return jsonify({"success": False, "error": "IP name not found"}), 404
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/ip-evolution/<ip>', methods=['GET'])
def get_ip_evolution(ip):
    """
    Return how an IP appears across recent scans (history).
    ---
    tags: [Config]
    parameters:
      - in: path
        name: ip
        schema: {type: string}
        required: true
      - in: query
        name: limit
        schema: {type: integer, default: 10}
    """
    try:
        ip = ip.replace('-', '.')
        limit = request.args.get('limit', 10, type=int)
        evolution = db.get_ip_evolution(ip, limit)
        return jsonify({"success": True, "data": evolution})
    except Exception as e:
        return server_error(e)


# ============================================================
# Trusted ranges
# ============================================================

@config_bp.route('/api/trusted-range', methods=['POST'])
@role_required('analyst')
def add_trusted_range():
    """
    Add a trusted CIDR range.
    ---
    tags: [Config]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              cidr: {type: string}
              description: {type: string}
    """
    try:
        data = request.json
        cidr = data.get('cidr')
        description = data.get('description', '')

        if not cidr:
            return jsonify({"success": False, "error": "CIDR required"}), 400

        settings = load_settings()
        if 'trusted_ranges' not in settings:
            settings['trusted_ranges'] = []

        for range_item in settings['trusted_ranges']:
            if range_item['cidr'] == cidr:
                return jsonify({"success": False, "error": "Range already exists"}), 400

        settings['trusted_ranges'].append({"cidr": cidr, "description": description})

        if save_settings(settings):
            return jsonify({"success": True, "message": "Trusted range added"})
        else:
            return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/trusted-range/<cidr>', methods=['DELETE'])
@role_required('analyst')
def delete_trusted_range(cidr):
    """
    Remove a trusted CIDR range. URL-encode '/' as '-'.
    ---
    tags: [Config]
    parameters:
      - in: path
        name: cidr
        schema: {type: string}
        required: true
    """
    try:
        settings = load_settings()
        if 'trusted_ranges' not in settings:
            return jsonify({"success": False, "error": "No trusted ranges found"}), 404

        cidr = cidr.replace('-', '/')
        original_len = len(settings['trusted_ranges'])
        settings['trusted_ranges'] = [r for r in settings['trusted_ranges'] if r['cidr'] != cidr]

        if len(settings['trusted_ranges']) == original_len:
            return jsonify({"success": False, "error": "Range not found"}), 404

        if save_settings(settings):
            return jsonify({"success": True, "message": "Trusted range removed"})
        else:
            return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return server_error(e)


# ============================================================
# SOC IPs — alerts whose src/dst falls under one of these CIDRs
# get a "SOC" badge so the analyst can spot pentest/scan traffic
# at a glance. The badge does NOT change severity or triage state.
# ============================================================

@config_bp.route('/api/soc-ips', methods=['GET'])
@role_required('viewer')
def list_soc_ips():
    """
    List configured SOC IP ranges + the default match mode.
    ---
    tags: [Config]
    """
    try:
        settings = load_settings()
        from soc import VALID_MATCH_MODES, DEFAULT_MATCH_MODE
        return jsonify({
            "success": True,
            "soc_ips": settings.get('soc_ips') or [],
            "default_match_mode": settings.get('soc_default_match_mode')
                                  or DEFAULT_MATCH_MODE,
            "valid_match_modes": list(VALID_MATCH_MODES),
        })
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/soc-ips', methods=['POST'])
@role_required('analyst')
def add_soc_ip():
    """
    Register a SOC CIDR range. Use match_mode='either' (default) unless you
    have a reason to limit to src_only or dst_only.
    ---
    tags: [Config]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              cidr: {type: string}
              description: {type: string}
              match_mode: {type: string, enum: [either, src_only, dst_only]}
    """
    import ipaddress
    from soc import VALID_MATCH_MODES, DEFAULT_MATCH_MODE
    try:
        data = request.json or {}
        cidr = (data.get('cidr') or '').strip()
        description = (data.get('description') or '').strip()
        match_mode = data.get('match_mode') or DEFAULT_MATCH_MODE

        if not cidr:
            return jsonify({"success": False, "error": "CIDR required"}), 400
        try:
            ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "invalid CIDR"}), 400
        if match_mode not in VALID_MATCH_MODES:
            return jsonify({"success": False,
                            "error": f"match_mode must be one of {list(VALID_MATCH_MODES)}"}), 400

        settings = load_settings()
        settings.setdefault('soc_ips', [])
        for r in settings['soc_ips']:
            if r.get('cidr') == cidr:
                return jsonify({"success": False, "error": "CIDR already registered"}), 400

        settings['soc_ips'].append({
            "cidr": cidr,
            "description": description,
            "match_mode": match_mode,
        })

        if save_settings(settings):
            audit_event(action='add_soc_ip', target_type='soc_ip', target_id=cidr,
                        extra={'match_mode': match_mode})
            return jsonify({"success": True, "message": "SOC IP added"})
        return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/soc-ips/<path:cidr>', methods=['DELETE'])
@role_required('analyst')
def delete_soc_ip(cidr):
    """
    Remove a SOC CIDR range. URL-encode '/' as '-'.
    ---
    tags: [Config]
    parameters:
      - in: path
        name: cidr
        schema: {type: string}
        required: true
    """
    try:
        settings = load_settings()
        if 'soc_ips' not in settings:
            return jsonify({"success": False, "error": "No SOC IPs registered"}), 404

        cidr = cidr.replace('-', '/')
        original = len(settings['soc_ips'])
        settings['soc_ips'] = [r for r in settings['soc_ips'] if r.get('cidr') != cidr]
        if len(settings['soc_ips']) == original:
            return jsonify({"success": False, "error": "CIDR not found"}), 404

        if save_settings(settings):
            audit_event(action='delete_soc_ip', target_type='soc_ip', target_id=cidr)
            return jsonify({"success": True, "message": "SOC IP removed"})
        return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return server_error(e)


@config_bp.route('/api/soc-default-match-mode', methods=['POST'])
@role_required('analyst')
def set_soc_default_match_mode():
    """
    Update the fallback match mode applied to SOC ranges that don't declare one.
    ---
    tags: [Config]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              match_mode: {type: string, enum: [either, src_only, dst_only]}
    """
    from soc import VALID_MATCH_MODES
    try:
        data = request.json or {}
        match_mode = data.get('match_mode')
        if match_mode not in VALID_MATCH_MODES:
            return jsonify({"success": False,
                            "error": f"match_mode must be one of {list(VALID_MATCH_MODES)}"}), 400
        settings = load_settings()
        settings['soc_default_match_mode'] = match_mode
        if save_settings(settings):
            audit_event(action='set_soc_default_match_mode',
                        target_type='soc_default', target_id=match_mode)
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return server_error(e)
