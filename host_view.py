"""
Per-machine view of analysis results.

The engine tags every per-IP row and alert with the machine (host_key) the
address belonged to IN THAT CAPTURE (see pcap_analyzer/hosts.py). This module
joins that with the machines stored in the DB (user-edited names, manual
bindings, removed bindings) and builds ``results['hosts_view']``: one entry
per machine with its IPv4/IPv6 addresses and the traffic totals of all of
them summed.

Resolution order for an IP:
  1. a MANUAL binding in the DB (user decision, also applies to old scans);
  2. the engine's host_key for this capture, unless the user has since
     removed that binding;
  3. the DB's current automatic owner (aggregated multi-scan view, where the
     rows carry no host_key).

Per-IP analysis is untouched: this only relabels rows and adds the totals.
"""

import database as db

_TOTAL_FIELDS = ('packets_sent', 'packets_received', 'bytes_sent', 'bytes_received')


def _num(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def attach_host_view(results):
    """Annotate `results` in place and add results['hosts_view']."""
    try:
        db_hosts = db.list_hosts()
        ip_map = db.get_ip_host_map()
    except Exception as e:
        print(f"[host_view] host data unavailable: {e}")
        return results

    by_key = {h['host_key']: h for h in db_hosts}
    by_id = {h['id']: h for h in db_hosts}
    manual_owner = {}
    excluded = set()
    for h in db_hosts:
        for b in h.get('ips') or []:
            if b.get('excluded'):
                excluded.add((h['host_key'], b['ip']))
            elif b.get('source') == 'manual':
                manual_owner[b['ip']] = h

    def resolve(ip, engine_key=None):
        if not ip:
            return None
        if ip in manual_owner:
            return manual_owner[ip]
        if engine_key and (engine_key, ip) not in excluded and engine_key in by_key:
            return by_key[engine_key]
        if engine_key:
            return None  # the capture saw it on a machine, then the user removed it
        current = ip_map.get(ip)
        if current and current.get('source') != 'manual':
            return by_id.get(current['id'])
        return None

    views = {}

    def view_for(h):
        v = views.get(h['id'])
        if v is None:
            v = views[h['id']] = {
                'id': h['id'],
                'host_key': h['host_key'],
                'mac': h.get('mac_address'),
                'is_manual': bool(h.get('is_manual')),
                'name': h.get('display_name') or '',
                'discovered_name': h.get('discovered_name'),
                'discovered_name_previous': h.get('discovered_name_previous'),
                'description': h.get('description'),
                'device_type': h.get('device_type'),
                'addresses': {},
                'protocols': set(),
                'alert_count': 0,
                'risk_score': 0,
                'is_local': False,
                **{f: 0 for f in _TOTAL_FIELDS},
            }
            for b in h.get('ips') or []:
                if not b.get('excluded'):
                    v['addresses'][b['ip']] = {
                        'ip': b['ip'], 'family': b.get('family'),
                        'scope': b.get('scope'), 'source': b.get('source'),
                        'in_view': False,
                    }
        return v

    for row in results.get('ips') or []:
        h = resolve(row.get('ip'), row.get('host_key'))
        if h is None:
            continue
        row['host_id'] = h['id']
        row['host_name'] = h.get('display_name') or ''
        if h.get('display_name'):
            row['name'] = h['display_name']
        if h.get('device_type'):
            row['device_type'] = h['device_type']
        v = view_for(h)
        addr = v['addresses'].setdefault(row['ip'], {
            'ip': row['ip'], 'family': 6 if ':' in row['ip'] else 4,
            'scope': None, 'source': 'auto', 'in_view': False,
        })
        addr['in_view'] = True
        for f in _TOTAL_FIELDS:
            addr[f] = _num(row.get(f))
            v[f] += _num(row.get(f))
        v['alert_count'] += _num(row.get('alert_count'))
        v['risk_score'] = max(v['risk_score'], _num(row.get('risk_score')))
        v['is_local'] = v['is_local'] or bool(row.get('is_local'))
        v['protocols'].update(row.get('protocols') or [])

    # Machines the capture saw only through ARP/NDP/DHCP (no traffic rows).
    for eh in results.get('hosts') or []:
        h = by_key.get(eh.get('host_key'))
        if h is not None:
            view_for(h)

    for proto_rows in (results.get('protocol_ips') or {}).values():
        for row in proto_rows:
            h = resolve(row.get('ip'), None)
            if h is not None and h.get('display_name'):
                row['name'] = h['display_name']

    for alert in results.get('alerts') or []:
        details = alert.get('details') if isinstance(alert.get('details'), dict) else {}
        h = resolve(alert.get('ip'), details.get('host_key'))
        if h is not None:
            alert['host_id'] = h['id']
            alert['host_name'] = h.get('display_name') or ''

    out = []
    for v in views.values():
        addrs = sorted(v['addresses'].values(),
                       key=lambda a: (a.get('family') or 9, a['ip']))
        v['addresses'] = addrs
        v['ipv4'] = [a['ip'] for a in addrs if a.get('family') == 4]
        v['ipv6'] = [a['ip'] for a in addrs if a.get('family') == 6]
        v['protocols'] = sorted(v['protocols'])
        out.append(v)
    out.sort(key=lambda v: v['bytes_sent'] + v['bytes_received'], reverse=True)
    results['hosts_view'] = out
    return results
