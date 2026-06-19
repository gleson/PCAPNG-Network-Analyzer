"""
Alert triage, suppression rules, FP signatures, and outbound webhooks.
---
tags: [Alerts]
"""

from datetime import datetime

from flask import Blueprint, request, jsonify

import database as db
from auth import role_required

from .common import audit_event, load_settings, server_error


alerts_bp = Blueprint('alerts', __name__)


# ============================================================
# Alerts
# ============================================================

@alerts_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    List alerts for a scan with triage state.
    ---
    tags: [Alerts]
    parameters:
      - in: query
        name: scan_id
        schema: {type: integer}
        required: true
      - in: query
        name: status
        schema: {type: string, enum: [analisar, falso_positivo, resolvido, sem_risco]}
    """
    scan_id = request.args.get('scan_id', type=int)
    if not scan_id:
        return jsonify({"success": False, "error": "scan_id is required"}), 400
    status = request.args.get('status') or None
    if status and status not in db.VALID_TRIAGE_STATUSES:
        return jsonify({"success": False, "error": f"invalid status; allowed: {sorted(db.VALID_TRIAGE_STATUSES)}"}), 400
    try:
        rows = db.get_alerts_by_scan(scan_id, status=status)
        return jsonify({"success": True, "alerts": rows, "count": len(rows)})
    except Exception as e:
        return server_error(e)


@alerts_bp.route('/api/alerts/<int:alert_id>/triage', methods=['POST'])
@role_required('analyst')
def triage_alert(alert_id):
    """
    Update an alert's triage state. Marking 'falso_positivo' trains the FP classifier.
    ---
    tags: [Alerts]
    parameters:
      - in: path
        name: alert_id
        schema: {type: integer}
        required: true
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              status: {type: string, enum: [analisar, falso_positivo, resolvido, sem_risco]}
              note: {type: string}
              assignee: {type: string}
    """
    data = request.get_json(silent=True) or {}
    status = data.get('status')
    note = data.get('note')
    assignee = data.get('assignee')
    if status is None and note is None and assignee is None:
        return jsonify({"success": False, "error": "no fields to update (status, note, assignee)"}), 400
    try:
        row = db.update_alert_triage(alert_id, status=status, note=note, assignee=assignee)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return server_error(e)
    if not row:
        return jsonify({"success": False, "error": "alert not found"}), 404
    audit_event(action='triage_alert', target_type='alert', target_id=alert_id,
                extra={'status': status, 'has_note': bool(note), 'has_assignee': bool(assignee)})
    return jsonify({"success": True, "alert": row})


# Cap one batch so a single request can't build an unbounded statement/audit row.
_MAX_BULK_TRIAGE = 5000


@alerts_bp.route('/api/alerts/triage-bulk', methods=['POST'])
@role_required('analyst')
def triage_alerts_bulk():
    """
    Apply one triage update to many alerts in a single request (e.g. "mark all
    filtered as false positive"). One UPDATE + one audit row instead of N POSTs.
    ---
    tags: [Alerts]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              alert_ids: {type: array, items: {type: integer}}
              status: {type: string, enum: [analisar, falso_positivo, resolvido, sem_risco]}
              note: {type: string}
              assignee: {type: string}
    """
    data = request.get_json(silent=True) or {}
    alert_ids = data.get('alert_ids')
    status = data.get('status')
    note = data.get('note')
    assignee = data.get('assignee')
    if not isinstance(alert_ids, list) or not alert_ids:
        return jsonify({"success": False, "error": "alert_ids (non-empty list) is required"}), 400
    if len(alert_ids) > _MAX_BULK_TRIAGE:
        return jsonify({"success": False,
                        "error": f"too many alerts in one request (max {_MAX_BULK_TRIAGE})"}), 400
    if status is None and note is None and assignee is None:
        return jsonify({"success": False, "error": "no fields to update (status, note, assignee)"}), 400
    try:
        rows = db.update_alerts_triage_bulk(alert_ids, status=status, note=note, assignee=assignee)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return server_error(e)
    audit_event(action='triage_alerts_bulk', target_type='alert', target_id=None,
                extra={'status': status, 'updated': len(rows), 'requested': len(alert_ids),
                       'has_note': bool(note), 'has_assignee': bool(assignee)})
    return jsonify({"success": True, "updated": len(rows), "alerts": rows})


# ============================================================
# Suppression rules
# ============================================================

@alerts_bp.route('/api/suppression-rules', methods=['GET'])
def list_suppression_rules_api():
    """
    List suppression (whitelist) rules.
    ---
    tags: [Alerts]
    """
    try:
        return jsonify({"success": True, "rules": db.list_suppression_rules()})
    except Exception as e:
        return server_error(e)


@alerts_bp.route('/api/suppression-rules', methods=['POST'])
@role_required('analyst')
def create_suppression_rule_api():
    """
    Create a suppression rule (at least one of title_pattern/category/src_ip/src_cidr).
    ---
    tags: [Alerts]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              title_pattern: {type: string}
              category: {type: string}
              src_ip: {type: string}
              src_cidr: {type: string}
              reason: {type: string}
              enabled: {type: boolean, default: true}
    """
    data = request.get_json(silent=True) or {}
    try:
        rule = db.create_suppression_rule(
            title_pattern=data.get('title_pattern'),
            category=data.get('category'),
            src_ip=data.get('src_ip'),
            src_cidr=data.get('src_cidr'),
            reason=data.get('reason'),
            enabled=bool(data.get('enabled', True)),
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return server_error(e)
    audit_event(action='create_suppression_rule', target_type='suppression_rule',
                target_id=rule.get('id'), extra={k: data.get(k) for k in
                                                 ('title_pattern', 'category', 'src_ip', 'src_cidr')})
    return jsonify({"success": True, "rule": rule}), 201


@alerts_bp.route('/api/suppression-rules/<int:rule_id>', methods=['DELETE'])
@role_required('analyst')
def delete_suppression_rule_api(rule_id):
    """
    Delete a suppression rule.
    ---
    tags: [Alerts]
    parameters:
      - in: path
        name: rule_id
        schema: {type: integer}
        required: true
    """
    try:
        deleted = db.delete_suppression_rule(rule_id)
    except Exception as e:
        return server_error(e)
    if not deleted:
        return jsonify({"success": False, "error": "rule not found"}), 404
    audit_event(action='delete_suppression_rule', target_type='suppression_rule', target_id=rule_id)
    return jsonify({"success": True})


@alerts_bp.route('/api/suppression-rules/<int:rule_id>/enabled', methods=['POST'])
@role_required('analyst')
def set_suppression_rule_enabled_api(rule_id):
    """
    Enable/disable a suppression rule.
    ---
    tags: [Alerts]
    parameters:
      - in: path
        name: rule_id
        schema: {type: integer}
        required: true
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              enabled: {type: boolean}
    """
    data = request.get_json(silent=True) or {}
    if 'enabled' not in data:
        return jsonify({"success": False, "error": "enabled (bool) is required"}), 400
    try:
        ok = db.set_suppression_rule_enabled(rule_id, bool(data['enabled']))
    except Exception as e:
        return server_error(e)
    if not ok:
        return jsonify({"success": False, "error": "rule not found"}), 404
    audit_event(action='toggle_suppression_rule', target_type='suppression_rule',
                target_id=rule_id, extra={'enabled': bool(data['enabled'])})
    return jsonify({"success": True})


# ============================================================
# Learned false-positive signatures
# ============================================================

@alerts_bp.route('/api/fp-signatures', methods=['GET'])
def list_fp_signatures_api():
    """
    List learned FP signatures (auto-silencing rules).
    ---
    tags: [Alerts]
    """
    try:
        return jsonify({"success": True, "signatures": db.get_active_fp_signatures()})
    except Exception as e:
        return server_error(e)


@alerts_bp.route('/api/fp-signatures/<int:sig_id>', methods=['DELETE'])
@role_required('analyst')
def delete_fp_signature_api(sig_id):
    """
    Forget a learned FP signature.
    ---
    tags: [Alerts]
    parameters:
      - in: path
        name: sig_id
        schema: {type: integer}
        required: true
    """
    try:
        deleted = db.delete_fp_signature(sig_id)
    except Exception as e:
        return server_error(e)
    if not deleted:
        return jsonify({"success": False, "error": "signature not found"}), 404
    audit_event(action='delete_fp_signature', target_type='fp_signature', target_id=sig_id)
    return jsonify({"success": True})


# ============================================================
# Webhooks
# ============================================================

@alerts_bp.route('/api/webhooks', methods=['GET'])
def list_webhooks_api():
    """
    List configured outbound webhooks.
    ---
    tags: [Alerts]
    """
    try:
        return jsonify({"success": True, "webhooks": db.list_webhooks()})
    except Exception as e:
        return server_error(e)


@alerts_bp.route('/api/webhooks', methods=['POST'])
@role_required('analyst')
def create_webhook_api():
    """
    Create an alert webhook (Slack/Teams/generic/syslog/email).
    ---
    tags: [Alerts]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              name: {type: string}
              type: {type: string, enum: [slack, teams, generic, syslog, email]}
              target: {type: string}
              min_severity: {type: string, default: high}
              categories: {oneOf: [{type: array, items: {type: string}}, {type: string}]}
              extra: {type: object}
              enabled: {type: boolean, default: true}
    """
    data = request.get_json(silent=True) or {}
    try:
        rid = db.create_webhook(
            name=data.get('name'),
            type=data.get('type'),
            target=data.get('target'),
            min_severity=data.get('min_severity', 'high'),
            categories=data.get('categories'),
            extra=data.get('extra'),
            enabled=bool(data.get('enabled', True)),
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return server_error(e)
    audit_event(action='create_webhook', target_type='webhook', target_id=rid,
                extra={'type': data.get('type'), 'name': data.get('name')})
    return jsonify({"success": True, "id": rid}), 201


@alerts_bp.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
@role_required('analyst')
def delete_webhook_api(webhook_id):
    """
    Delete a webhook.
    ---
    tags: [Alerts]
    parameters:
      - in: path
        name: webhook_id
        schema: {type: integer}
        required: true
    """
    try:
        ok = db.delete_webhook(webhook_id)
    except Exception as e:
        return server_error(e)
    if not ok:
        return jsonify({"success": False, "error": "webhook not found"}), 404
    audit_event(action='delete_webhook', target_type='webhook', target_id=webhook_id)
    return jsonify({"success": True})


@alerts_bp.route('/api/webhooks/<int:webhook_id>/enabled', methods=['POST'])
@role_required('analyst')
def set_webhook_enabled_api(webhook_id):
    """
    Enable/disable a webhook.
    ---
    tags: [Alerts]
    parameters:
      - in: path
        name: webhook_id
        schema: {type: integer}
        required: true
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              enabled: {type: boolean}
    """
    data = request.get_json(silent=True) or {}
    if 'enabled' not in data:
        return jsonify({"success": False, "error": "enabled (bool) is required"}), 400
    try:
        ok = db.set_webhook_enabled(webhook_id, bool(data['enabled']))
    except Exception as e:
        return server_error(e)
    if not ok:
        return jsonify({"success": False, "error": "webhook not found"}), 404
    audit_event(action='toggle_webhook', target_type='webhook', target_id=webhook_id,
                extra={'enabled': bool(data['enabled'])})
    return jsonify({"success": True})


@alerts_bp.route('/api/webhooks/<int:webhook_id>/test', methods=['POST'])
@role_required('analyst')
def test_webhook_api(webhook_id):
    """
    Send a single synthetic alert through the webhook to verify connectivity.
    ---
    tags: [Alerts]
    parameters:
      - in: path
        name: webhook_id
        schema: {type: integer}
        required: true
    """
    try:
        rows = db.list_webhooks()
        hook = next((h for h in rows if h['id'] == webhook_id), None)
        if not hook:
            return jsonify({"success": False, "error": "webhook not found"}), 404
        from notifications import _send_to_webhook
        synthetic = [{
            "severity": "high",
            "category": "test",
            "title": "PCAP Analyzer Webhook Test",
            "description": "If you can read this, your webhook is wired up correctly.",
            "ip": "127.0.0.1",
            "details": {},
        }]
        ctx = {"scan_id": None, "filename": "(test)",
               "analyzed_at": datetime.now().isoformat(), "total_alerts": 1}
        err = _send_to_webhook(hook, synthetic, ctx, load_settings())
        db.mark_webhook_result(webhook_id, error=err)
        if err:
            return jsonify({"success": False, "error": err}), 502
        audit_event(action='test_webhook', target_type='webhook', target_id=webhook_id)
        return jsonify({"success": True})
    except Exception as e:
        return server_error(e)
