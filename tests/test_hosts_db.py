"""Machine (host) persistence: naming rules, manual bindings, view merge.

Runs against the disposable Postgres of the Docker test suite (DATABASE_URL);
skips when psycopg2 or the database is unavailable.
"""

import pytest

pytest.importorskip("psycopg2")

import database as db  # noqa: E402

MAC_A = "00:1a:2b:3c:4d:5e"
MAC_B = "00:1a:2b:3c:4d:5f"
V4_A = "192.168.50.55"
LL_A = "fe80::fb21:3bcc:4b6d:5b01"
SCAN_TIME = "2026-09-23T10:00:00"


@pytest.fixture(autouse=True)
def clean_db():
    try:
        db.init_database()
        with db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("TRUNCATE hosts, host_ips, ip_names RESTART IDENTITY CASCADE")
            conn.commit()
    except Exception as e:  # pragma: no cover - environment dependent
        pytest.skip(f"database unavailable: {e}")
    yield


def _host(mac=MAC_A, name=None, addrs=((V4_A, 4, "v4_private"), (LL_A, 6, "v6_link_local"))):
    return {
        "host_key": mac, "mac": mac, "manual": False,
        "discovered_name": name,
        "addresses": [
            {"ip": ip, "family": fam, "scope": scope, "binding": "auto",
             "first_ts": 1_790_000_000.0, "last_ts": 1_790_000_100.0}
            for ip, fam, scope in addrs
        ],
    }


def _by_key(key):
    return next(h for h in db.list_hosts() if h["host_key"] == key)


# ----------------------------------------------------------------- naming

def test_first_discovery_copies_name_and_binds_both_families():
    db.record_hosts(1, SCAN_TIME, [_host(name="CDVHS02")])
    h = _by_key(MAC_A)
    assert h["discovered_name"] == "CDVHS02"
    assert h["name"] == "CDVHS02"
    assert h["name_edited"] is False
    assert {b["ip"] for b in h["ips"]} == {V4_A, LL_A}


def test_user_name_is_never_overwritten_and_network_rename_is_flagged():
    db.record_hosts(1, SCAN_TIME, [_host(name="CDVHS02")])
    hid = _by_key(MAC_A)["id"]
    db.update_host(hid, name="PDH02")
    db.record_hosts(2, SCAN_TIME, [_host(name="CDVHS05")])
    h = db.get_host(hid)
    assert h["name"] == "PDH02"
    assert h["discovered_name"] == "CDVHS05"
    assert h["discovered_name_previous"] == "CDVHS02"
    assert h["name_changed_on_network"] is True
    db.update_host(hid, acknowledge_name_change=True)
    assert db.get_host(hid)["name_changed_on_network"] is False


def test_legacy_ip_label_becomes_the_machine_name():
    # The user had named the IPv4 "PDH02" before machines existed.
    db.set_ip_name(V4_A, "PDH02", "estação", "Computador")
    db.record_hosts(1, SCAN_TIME, [_host(name="CDVHS02")])
    h = _by_key(MAC_A)
    assert h["name"] == "PDH02"
    assert h["discovered_name"] == "CDVHS02"
    assert h["name_edited"] is True


def test_empty_name_resets_to_discovered():
    db.record_hosts(1, SCAN_TIME, [_host(name="CDVHS02")])
    hid = _by_key(MAC_A)["id"]
    db.update_host(hid, name="PDH02")
    h = db.update_host(hid, name="")
    assert h["name"] == "CDVHS02" and h["name_edited"] is False


# --------------------------------------------------------------- bindings

def test_manual_bind_and_unbind_round_trip():
    db.record_hosts(1, SCAN_TIME, [_host()])
    hid = _by_key(MAC_A)["id"]
    assert db.bind_host_ip(hid, "2804:14c:1:2::55", created_by="tester")
    cfg = db.get_host_binding_settings()
    assert {"host_key": MAC_A, "ip": "2804:14c:1:2::55", "mac": MAC_A} in cfg["manual"]
    assert db.unbind_host_ip(hid, "2804:14c:1:2::55") == "deleted"
    # Removing an AUTOMATIC binding excludes it for future captures.
    assert db.unbind_host_ip(hid, LL_A) == "excluded"
    assert {"host_key": MAC_A, "ip": LL_A} in db.get_host_binding_settings()["excluded"]
    db.record_hosts(2, SCAN_TIME, [_host()])  # capture sees it again
    assert db.get_host_binding_settings()["excluded"] == [{"host_key": MAC_A, "ip": LL_A}]
    assert LL_A not in db.get_ip_host_map()


def test_bind_rejects_non_host_addresses():
    hid = db.create_manual_host("Servidor remoto")
    for bad in ("ff02::1", "255.255.255.255", "not-an-ip"):
        with pytest.raises(ValueError):
            db.bind_host_ip(hid, bad)


def test_manual_bind_moves_ip_between_manual_hosts():
    a = db.create_manual_host("A")
    b = db.create_manual_host("B")
    db.bind_host_ip(a, "10.20.0.5")
    db.bind_host_ip(b, "10.20.0.5")
    assert db.get_ip_host_map()["10.20.0.5"]["id"] == b
    assert db.get_host(a)["ips"] == []


def test_only_manual_hosts_can_be_deleted():
    db.record_hosts(1, SCAN_TIME, [_host()])
    with pytest.raises(ValueError):
        db.delete_host(_by_key(MAC_A)["id"])
    mid = db.create_manual_host("Servidor remoto")
    assert db.delete_host(mid) is True


def test_ip_map_prefers_manual_then_most_recent():
    db.record_hosts(1, SCAN_TIME, [_host(MAC_A, addrs=((V4_A, 4, "v4_private"),))])
    newer = _host(MAC_B, addrs=((V4_A, 4, "v4_private"),))
    for a in newer["addresses"]:
        a["last_ts"] += 10_000  # DHCP handed the IP to B later
    db.record_hosts(2, SCAN_TIME, [newer])
    assert db.get_ip_host_map()[V4_A]["host_key"] == MAC_B
    db.bind_host_ip(_by_key(MAC_A)["id"], V4_A)
    assert db.get_ip_host_map()[V4_A]["host_key"] == MAC_A


# ------------------------------------------------------------------- view

def test_host_view_sums_ipv4_and_ipv6_traffic():
    from host_view import attach_host_view
    db.record_hosts(1, SCAN_TIME, [_host(name="CDVHS02")])
    hid = _by_key(MAC_A)["id"]
    db.update_host(hid, name="PDH02")
    results = {
        "hosts": [_host(name="CDVHS02")],
        "ips": [
            {"ip": V4_A, "host_key": MAC_A, "packets_sent": 10, "packets_received": 5,
             "bytes_sent": 1000, "bytes_received": 500, "alert_count": 1,
             "protocols": ["TCP"], "is_local": True},
            {"ip": LL_A, "host_key": MAC_A, "packets_sent": 3, "packets_received": 2,
             "bytes_sent": 300, "bytes_received": 200, "alert_count": 2,
             "protocols": ["ICMPv6"], "is_local": True},
            {"ip": "8.8.8.8", "packets_sent": 1, "bytes_sent": 1},
        ],
        "alerts": [{"ip": LL_A, "details": {"host_key": MAC_A}}],
    }
    attach_host_view(results)
    view = results["hosts_view"]
    assert len(view) == 1
    v = view[0]
    assert v["name"] == "PDH02" and v["discovered_name"] == "CDVHS02"
    assert v["bytes_sent"] == 1300 and v["bytes_received"] == 700
    assert v["alert_count"] == 3
    assert v["ipv4"] == [V4_A] and v["ipv6"] == [LL_A]
    assert v["protocols"] == ["ICMPv6", "TCP"]
    rows = {r["ip"]: r for r in results["ips"]}
    assert rows[V4_A]["name"] == "PDH02" and rows[LL_A]["host_id"] == hid
    assert "host_id" not in rows["8.8.8.8"]
    assert results["alerts"][0]["host_name"] == "PDH02"


def test_host_view_honours_later_unbind_on_old_scan():
    from host_view import attach_host_view
    db.record_hosts(1, SCAN_TIME, [_host()])
    db.unbind_host_ip(_by_key(MAC_A)["id"], LL_A)
    results = {"ips": [{"ip": LL_A, "host_key": MAC_A, "bytes_sent": 5}]}
    attach_host_view(results)
    assert "host_id" not in results["ips"][0]
