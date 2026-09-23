"""Suppression-rule matching, scope guardrails, and audit hash primitive.

These live in database.py, which imports psycopg2 at module load. The pure
functions under test never open a connection, but the import needs the driver,
so the whole module skips when psycopg2 is unavailable (local pure-python runs)
and executes in the Docker suite where it is installed.
"""
import pytest

pytest.importorskip("psycopg2")

import database as db  # noqa: E402


# ============================================================
#  Canonical src/dst matching
# ============================================================

def _scan_alert(**over):
    base = {
        'title': 'Port Scan Detected',
        'category': 'scan',
        'severity': 'medium',
        'src_ips': ['10.0.0.5'],
        'dst_ips': ['10.0.0.9'],
    }
    base.update(over)
    return base


def test_match_source_only():
    a = _scan_alert()
    assert db._alert_matches_rule(a, {'src_ip': '10.0.0.5'}) is True
    assert db._alert_matches_rule(a, {'src_ip': '10.0.0.99'}) is False


def test_match_source_and_destination():
    a = _scan_alert()
    assert db._alert_matches_rule(a, {'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.9'}) is True
    # Right source, wrong destination -> no match (AND semantics).
    assert db._alert_matches_rule(a, {'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.7'}) is False


def test_match_source_destination_and_category():
    a = _scan_alert()
    assert db._alert_matches_rule(
        a, {'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.9', 'category': 'scan'}) is True
    assert db._alert_matches_rule(
        a, {'src_ip': '10.0.0.5', 'category': 'exfiltration'}) is False


def test_match_by_cidr():
    a = _scan_alert()
    assert db._alert_matches_rule(a, {'src_cidr': '10.0.0.0/24'}) is True
    assert db._alert_matches_rule(a, {'src_cidr': '10.1.0.0/16'}) is False
    assert db._alert_matches_rule(a, {'dst_cidr': '10.0.0.0/24'}) is True


def test_match_title_substring():
    a = _scan_alert()
    assert db._alert_matches_rule(a, {'src_ip': '10.0.0.5', 'title_pattern': 'Port Scan'}) is True
    assert db._alert_matches_rule(a, {'src_ip': '10.0.0.5', 'title_pattern': 'Beaconing'}) is False


def test_destination_rule_fails_closed_when_alert_has_no_destination():
    # Rule pins a destination but the alert carries none -> must NOT match, so a
    # dst-scoped rule can never silence an unrelated one-sided alert.
    a = {'title': 'x', 'category': 'c', 'src_ips': ['1.2.3.4']}
    assert db._alert_matches_rule(a, {'dst_ip': '9.9.9.9'}) is False


def test_side_ips_fallback_to_legacy_keys():
    # Alert that never went through normalize_alerts (no src_ips/dst_ips).
    a = {'title': 't', 'category': 'c', 'ip': '10.0.0.5',
         'details': {'dst': '10.0.0.9'}}
    assert db._alert_side_ips(a, 'src') == ['10.0.0.5']
    assert db._alert_side_ips(a, 'dst') == ['10.0.0.9']
    assert db._alert_matches_rule(a, {'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.9'}) is True


def test_evaluate_suppression_returns_first_matching_id():
    a = _scan_alert()
    rules = [
        {'id': 1, 'src_ip': '10.0.0.99'},          # no match
        {'id': 2, 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.9'},  # match
        {'id': 3, 'src_ip': '10.0.0.5'},           # would also match
    ]
    assert db.evaluate_suppression(a, rules) == 2


# ============================================================
#  Scope guardrails
# ============================================================

def test_validate_cidr_rejects_overbroad_ranges():
    with pytest.raises(ValueError):
        db._validate_suppression_cidr('0.0.0.0/0')
    with pytest.raises(ValueError):
        db._validate_suppression_cidr('10.0.0.0/4')   # broader than /8 floor
    with pytest.raises(ValueError):
        db._validate_suppression_cidr('::/0')
    # Reasonable ranges pass.
    assert db._validate_suppression_cidr('10.0.0.0/24').prefixlen == 24
    assert db._validate_suppression_cidr('10.0.0.0/8').prefixlen == 8


def test_create_rule_requires_an_endpoint():
    # A category- or title-only rule would suppress that class network-wide.
    with pytest.raises(ValueError):
        db.create_suppression_rule(category='scan')
    with pytest.raises(ValueError):
        db.create_suppression_rule(title_pattern='Port Scan')


def test_create_rule_rejects_garbage_ip():
    with pytest.raises(ValueError):
        db.create_suppression_rule(src_ip='not-an-ip')


# ============================================================
#  Audit hash primitive
# ============================================================

def test_audit_row_hash_is_deterministic():
    args = ('PREVHASH', '2026-07-22T10:00:00+00:00', 'admin', '1.2.3.4',
            'POST', '/api/suppression-rules', 'create_suppression_rule',
            'suppression_rule', '7', 201, '{"src_ip":"1.2.3.4"}')
    h1 = db._audit_row_hash(*args)
    h2 = db._audit_row_hash(*args)
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_audit_row_hash_changes_with_any_field():
    base = ['PREV', 'ts', 'admin', 'ip', 'POST', '/p', 'act', 'tt', 'tid', 200, None]
    baseline = db._audit_row_hash(*base)
    for i in range(len(base)):
        mutated = list(base)
        mutated[i] = 'TAMPERED' if mutated[i] != 'TAMPERED' else 'OTHER'
        assert db._audit_row_hash(*mutated) != baseline, f"field {i} not covered by hash"


def test_audit_row_hash_chains_on_prev_hash():
    # Same row content but a different predecessor hash yields a different hash,
    # which is what makes deleting an earlier row detectable.
    fields = ('ts', 'admin', 'ip', 'POST', '/p', 'act', 'tt', 'tid', 200, None)
    assert db._audit_row_hash('HASH_A', *fields) != db._audit_row_hash('HASH_B', *fields)
