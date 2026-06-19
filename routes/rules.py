"""
User-defined detection rules (data/rules/*.json).
---
tags: [Rules]
"""

import os
import json

from flask import Blueprint, request, jsonify

from auth import role_required

from .common import audit_event, server_error


rules_bp = Blueprint('rules', __name__, url_prefix='/api/user-rules')


@rules_bp.route('', methods=['GET'])
@role_required('analyst')
def list_user_rules_api():
    """
    List every rule file in data/rules/, with parsed contents and per-rule errors.
    ---
    tags: [Rules]
    """
    try:
        from user_rules import DEFAULT_RULES_DIR, _normalize_rule
        out = []
        if os.path.isdir(DEFAULT_RULES_DIR):
            for path in sorted(os.listdir(DEFAULT_RULES_DIR)):
                if not path.endswith('.json'):
                    continue
                full = os.path.join(DEFAULT_RULES_DIR, path)
                try:
                    with open(full, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    rules = data if isinstance(data, list) else [data]
                    parsed = []
                    errors = []
                    for r in rules:
                        try:
                            n = _normalize_rule(dict(r))
                            n['match'] = {k: v for k, v in n.get('match', {}).items()
                                          if not k.startswith('_')}
                            parsed.append(n)
                        except ValueError as e:
                            errors.append(str(e))
                    out.append({"file": path, "rules": parsed, "errors": errors})
                except Exception as e:
                    out.append({"file": path, "rules": [], "errors": [str(e)]})
        return jsonify({"success": True, "files": out})
    except Exception as e:
        return server_error(e)


@rules_bp.route('/<path:filename>', methods=['PUT'])
@role_required('admin')
def write_user_rule_file_api(filename):
    """
    Create or replace a user rule file. Validated before write.
    ---
    tags: [Rules]
    parameters:
      - in: path
        name: filename
        schema: {type: string}
        required: true
    requestBody:
      required: true
      content:
        application/json:
          schema:
            oneOf:
              - type: array
                items: {type: object}
              - type: object
    """
    if '/' in filename or '\\' in filename or filename.startswith('.'):
        return jsonify({"success": False, "error": "invalid filename"}), 400
    if not filename.endswith('.json'):
        return jsonify({"success": False, "error": "filename must end with .json"}), 400
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"success": False, "error": "JSON body required"}), 400

    rules = data if isinstance(data, list) else [data]
    try:
        from user_rules import _normalize_rule, DEFAULT_RULES_DIR
        for r in rules:
            _normalize_rule(dict(r))
    except (ValueError, TypeError) as e:
        return jsonify({"success": False, "error": f"invalid rule: {e}"}), 400

    os.makedirs(DEFAULT_RULES_DIR, exist_ok=True)
    full = os.path.join(DEFAULT_RULES_DIR, filename)
    try:
        with open(full, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2)
    except Exception as e:
        return server_error(e)
    audit_event(action='write_user_rule_file', target_type='user_rule_file',
                target_id=filename, extra={'rule_count': len(rules)})
    return jsonify({"success": True, "rule_count": len(rules)})


@rules_bp.route('/import', methods=['POST'])
@role_required('admin')
def import_rules_api():
    """
    Import Suricata (.rules) or Zeek (.sig) rules and persist them as JSON.

    Body forms:
      - {"text": "<rule text>", "format": "suricata"|"zeek"|null,
         "filename": "etopen-emerging.json"}
      - multipart/form-data with file=<.rules|.sig> (filename used as fallback id)

    The parsed rules are written under data/rules/<filename>.json. Each rule
    is validated through user_rules._normalize_rule before persistence;
    rules that fail validation are reported in `errors` and skipped.
    ---
    tags: [Rules]
    """
    text = None
    fmt = None
    out_filename = None

    if request.files.get('file'):
        upload = request.files['file']
        try:
            text = upload.read().decode('utf-8', errors='replace')
        except Exception as e:
            return jsonify({"success": False, "error": f"upload read failed: {e}"}), 400
        src_name = (upload.filename or 'imported').rsplit('.', 1)[0]
        out_filename = request.form.get('filename') or f"imported_{src_name}.json"
        fmt = request.form.get('format')
    else:
        body = request.get_json(silent=True) or {}
        text = body.get('text')
        fmt = body.get('format')
        out_filename = body.get('filename') or 'imported.json'

    if not text:
        return jsonify({"success": False, "error": "rule text is required"}), 400
    if '/' in out_filename or '\\' in out_filename or out_filename.startswith('.'):
        return jsonify({"success": False, "error": "invalid filename"}), 400
    if not out_filename.endswith('.json'):
        out_filename += '.json'

    try:
        from suricata_import import import_text
        from user_rules import _normalize_rule, DEFAULT_RULES_DIR
    except ImportError as e:
        return jsonify({"success": False, "error": f"importer unavailable: {e}"}), 500

    parsed = import_text(text, fmt=fmt, filename=out_filename)
    valid = []
    errors = list(parsed.get('errors', []))
    for raw in parsed.get('rules', []):
        try:
            _normalize_rule(dict(raw))
            valid.append(raw)
        except (ValueError, TypeError) as e:
            errors.append({"id": raw.get('id'), "error": str(e)})

    if not valid:
        return jsonify({
            "success": False,
            "error": "no valid rules parsed",
            "format": parsed.get('format'),
            "errors": errors,
        }), 400

    os.makedirs(DEFAULT_RULES_DIR, exist_ok=True)
    full = os.path.join(DEFAULT_RULES_DIR, out_filename)
    try:
        with open(full, 'w', encoding='utf-8') as f:
            json.dump(valid, f, indent=2)
    except Exception as e:
        return server_error(e)

    audit_event(action='import_rules', target_type='user_rule_file',
                target_id=out_filename,
                extra={'format': parsed.get('format'),
                       'imported': len(valid),
                       'errors': len(errors)})
    return jsonify({
        "success": True,
        "filename": out_filename,
        "format": parsed.get('format'),
        "imported": len(valid),
        "errors": errors,
    })


@rules_bp.route('/<path:filename>', methods=['DELETE'])
@role_required('admin')
def delete_user_rule_file_api(filename):
    """
    Delete a user rule file.
    ---
    tags: [Rules]
    parameters:
      - in: path
        name: filename
        schema: {type: string}
        required: true
    """
    if '/' in filename or '\\' in filename or filename.startswith('.'):
        return jsonify({"success": False, "error": "invalid filename"}), 400
    from user_rules import DEFAULT_RULES_DIR
    full = os.path.join(DEFAULT_RULES_DIR, filename)
    if not os.path.isfile(full):
        return jsonify({"success": False, "error": "file not found"}), 404
    try:
        os.remove(full)
    except Exception as e:
        return server_error(e)
    audit_event(action='delete_user_rule_file', target_type='user_rule_file',
                target_id=filename)
    return jsonify({"success": True})
