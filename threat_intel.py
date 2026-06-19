"""
Threat Intelligence Module
Aggregates multi-source IOC feeds for IP, domain and JA3 reputation lookups.

Free / no-key sources:
  - IPsum (stamparm/ipsum)            : malicious IP scoring
  - Tor exit nodes (torproject.org)   : Tor exit list
  - Feodo Tracker (abuse.ch)          : botnet C2 IPs
  - ThreatFox (abuse.ch)              : multi-IOC (ip, domain, url, hash)
  - URLhaus (abuse.ch)                : malicious URLs / hosts
  - SSLBL JA3 (abuse.ch)              : malicious TLS JA3 fingerprints

Optional / API key:
  - AbuseIPDB (ABUSEIPDB_API_KEY env) : IP confidence score
"""
import os
import csv
import io
import ipaddress
import re
import requests
import time
from datetime import datetime
from urllib.parse import urlparse
import database as db

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')

# ---- API key resolver ----
# For services that use settings['<svc>_url'] + creds (MISP/TAXII/CIRCL) the
# env var holds only the credential; URL/collection come from settings.
_ENV_MAP = {
    'abuseipdb':  'ABUSEIPDB_API_KEY',
    'virustotal': 'VIRUSTOTAL_API_KEY',
    'shodan':     'SHODAN_API_KEY',
    'greynoise':  'GREYNOISE_API_KEY',
    'otx':        'OTX_API_KEY',
    'circl':      'CIRCL_AUTH',          # "user:password"
    'misp':       'MISP_AUTH_KEY',
    'taxii':      'TAXII_AUTH',          # "user:password"
}

def _get_key(service, settings=None):
    """Return API key: settings dict (admin-saved) > env var > module-level constant."""
    if settings:
        key = (settings.get('api_keys') or {}).get(service, '')
        if key:
            return key
    env_key = _ENV_MAP.get(service)
    if env_key:
        val = os.environ.get(env_key, '')
        if val:
            return val
    if service == 'abuseipdb':
        return ABUSEIPDB_API_KEY
    return ''

# ---- Feed URLs ----
IPSUM_URL          = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
TOR_EXIT_URL       = 'https://check.torproject.org/torbulkexitlist'
FEODO_URL          = 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
THREATFOX_URL      = 'https://threatfox.abuse.ch/export/csv/recent/'
URLHAUS_URL        = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
SSLBL_JA3_URL      = 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv'

# Onda 7 — additional feeds.
CISA_KEV_URL       = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
SPAMHAUS_DROP_URL  = 'https://www.spamhaus.org/drop/drop.txt'
SPAMHAUS_EDROP_URL = 'https://www.spamhaus.org/drop/edrop.txt'

# ---- TTLs (hours) ----
TTL_HOURS = 24

# ---- In-memory caches (per-process) ----
_cache = {
    'ipsum':     {'data': {}, 'updated': None},
    'tor':       {'data': set(), 'updated': None},
    'feodo':     {'data': {}, 'updated': None},
    'threatfox': {'ips': {}, 'domains': {}, 'urls': {}, 'updated': None},
    'urlhaus':   {'hosts': {}, 'urls': {}, 'updated': None},
    'sslbl_ja3': {'data': {}, 'updated': None},
    # Onda 7 caches
    'cisa_kev':       {'data': {}, 'updated': None},
    'spamhaus_drop':  {'data': [], 'updated': None},   # list[(IPv4Network, sbl_id)]
    'spamhaus_edrop': {'data': [], 'updated': None},
    'otx':            {'ips': {}, 'domains': {}, 'hashes': {}, 'updated': None},
    'misp':           {'ips': {}, 'domains': {}, 'hashes': {}, 'urls': {}, 'updated': None},
    'taxii':          {'ips': {}, 'domains': {}, 'hashes': {}, 'updated': None},
}


def _is_fresh(key):
    upd = _cache[key].get('updated')
    if not upd:
        return False
    return (datetime.now() - upd).total_seconds() / 3600 < TTL_HOURS


def _http_get(url, timeout=20):
    try:
        resp = requests.get(url, timeout=timeout, headers={'User-Agent': 'pcap-analyzer/1.0'})
        if resp.status_code == 200:
            return resp.text
        print(f"[threat_intel] {url} returned HTTP {resp.status_code}")
    except Exception as e:
        print(f"[threat_intel] error fetching {url}: {e}")
    return None


# ============================================================
#  Feed loaders
# ============================================================

def load_ipsum_list():
    """IPsum: tab-separated `ip<TAB>score`. Score = number of blacklists listing it."""
    if _is_fresh('ipsum'):
        return _cache['ipsum']['data']
    text = _http_get(IPSUM_URL)
    if text is None:
        return _cache['ipsum']['data']
    ips = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) >= 2:
            try:
                ips[parts[0]] = int(parts[1])
            except ValueError:
                continue
    _cache['ipsum'] = {'data': ips, 'updated': datetime.now()}
    print(f"[threat_intel] IPsum loaded: {len(ips)} IPs")
    return ips


def load_tor_exit_nodes():
    """Tor exit list: plain-text, one IP per line."""
    if _is_fresh('tor'):
        return _cache['tor']['data']
    text = _http_get(TOR_EXIT_URL)
    if text is None:
        return _cache['tor']['data']
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            ips.add(line)
    _cache['tor'] = {'data': ips, 'updated': datetime.now()}
    print(f"[threat_intel] Tor exit nodes loaded: {len(ips)} IPs")
    return ips


def load_feodo_ips():
    """Feodo Tracker: plain-text IP blocklist (active botnet C2)."""
    if _is_fresh('feodo'):
        return _cache['feodo']['data']
    text = _http_get(FEODO_URL)
    if text is None:
        return _cache['feodo']['data']
    ips = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            ips[line] = 'Feodo-C2'
    _cache['feodo'] = {'data': ips, 'updated': datetime.now()}
    print(f"[threat_intel] Feodo Tracker loaded: {len(ips)} C2 IPs")
    return ips


def load_threatfox_iocs():
    """ThreatFox CSV: indexes IPs, domains and URLs by malware family."""
    if _is_fresh('threatfox'):
        return _cache['threatfox']
    text = _http_get(THREATFOX_URL)
    result = {'ips': {}, 'domains': {}, 'urls': {}, 'updated': datetime.now()}
    if text is None:
        _cache['threatfox']['updated'] = datetime.now()
        return _cache['threatfox']
    # ThreatFox CSV uses double-quoted fields, header lines prefixed with '#'.
    reader = csv.reader(io.StringIO(text), quotechar='"', skipinitialspace=True)
    for row in reader:
        if not row or row[0].startswith('#') or len(row) < 6:
            continue
        try:
            ioc_value = row[2].strip()
            ioc_type  = row[3].strip().lower()
            malware   = row[5].strip() if len(row) > 5 else ''
        except IndexError:
            continue
        entry = {'malware': malware, 'source': 'ThreatFox'}
        if ioc_type in ('ip:port', 'ip'):
            ip_only = ioc_value.split(':')[0]
            result['ips'][ip_only] = entry
        elif ioc_type == 'domain':
            result['domains'][ioc_value.lower()] = entry
        elif ioc_type == 'url':
            host = urlparse(ioc_value).hostname
            if host:
                result['domains'].setdefault(host.lower(), entry)
            result['urls'][ioc_value] = entry
    _cache['threatfox'] = result
    print(f"[threat_intel] ThreatFox loaded: {len(result['ips'])} IPs / "
          f"{len(result['domains'])} domains / {len(result['urls'])} URLs")
    return result


def load_urlhaus_urls():
    """URLhaus CSV: malicious URLs (extract host)."""
    if _is_fresh('urlhaus'):
        return _cache['urlhaus']
    text = _http_get(URLHAUS_URL)
    result = {'hosts': {}, 'urls': {}, 'updated': datetime.now()}
    if text is None:
        _cache['urlhaus']['updated'] = datetime.now()
        return _cache['urlhaus']
    reader = csv.reader(io.StringIO(text), quotechar='"', skipinitialspace=True)
    for row in reader:
        if not row or row[0].startswith('#') or len(row) < 8:
            continue
        try:
            url     = row[2].strip()
            status  = row[3].strip()
            threat  = row[5].strip() if len(row) > 5 else ''
            tags    = row[6].strip() if len(row) > 6 else ''
        except IndexError:
            continue
        if not url:
            continue
        host = urlparse(url).hostname
        entry = {'threat': threat, 'tags': tags, 'status': status, 'source': 'URLhaus'}
        result['urls'][url] = entry
        if host:
            result['hosts'].setdefault(host.lower(), entry)
    _cache['urlhaus'] = result
    print(f"[threat_intel] URLhaus loaded: {len(result['hosts'])} hosts / "
          f"{len(result['urls'])} URLs")
    return result


def load_sslbl_ja3():
    """SSLBL: JA3 fingerprints linked to malware families."""
    if _is_fresh('sslbl_ja3'):
        return _cache['sslbl_ja3']['data']
    text = _http_get(SSLBL_JA3_URL)
    if text is None:
        return _cache['sslbl_ja3']['data']
    ja3 = {}
    reader = csv.reader(io.StringIO(text), quotechar='"', skipinitialspace=True)
    for row in reader:
        if not row or row[0].startswith('#') or len(row) < 3:
            continue
        try:
            md5 = row[1].strip().lower()
            description = row[2].strip()
        except IndexError:
            continue
        if len(md5) == 32:
            ja3[md5] = description
    _cache['sslbl_ja3'] = {'data': ja3, 'updated': datetime.now()}
    print(f"[threat_intel] SSLBL JA3 loaded: {len(ja3)} fingerprints")
    return ja3


# ============================================================
#  Onda 7 — CISA KEV (no key)
# ============================================================

def load_cisa_kev():
    """CISA Known Exploited Vulnerabilities catalog (JSON).

    Indexed by CVE id (uppercase). Each entry preserves vendorProject, product,
    vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate,
    knownRansomwareCampaignUse.
    """
    if _is_fresh('cisa_kev'):
        return _cache['cisa_kev']['data']
    text = _http_get(CISA_KEV_URL, timeout=30)
    if text is None:
        return _cache['cisa_kev']['data']
    try:
        import json
        payload = json.loads(text)
    except Exception as e:
        print(f"[threat_intel] CISA KEV parse error: {e}")
        return _cache['cisa_kev']['data']
    catalog = {}
    for vuln in payload.get('vulnerabilities', []) or []:
        cve = (vuln.get('cveID') or '').upper()
        if not cve:
            continue
        catalog[cve] = {
            'cve': cve,
            'vendor': vuln.get('vendorProject', ''),
            'product': vuln.get('product', ''),
            'name': vuln.get('vulnerabilityName', ''),
            'date_added': vuln.get('dateAdded', ''),
            'short_description': vuln.get('shortDescription', ''),
            'required_action': vuln.get('requiredAction', ''),
            'due_date': vuln.get('dueDate', ''),
            'ransomware': (vuln.get('knownRansomwareCampaignUse', 'Unknown')
                           or '').lower() == 'known',
            'source': 'CISA KEV',
        }
    _cache['cisa_kev'] = {'data': catalog, 'updated': datetime.now()}
    print(f"[threat_intel] CISA KEV loaded: {len(catalog)} CVEs")
    return catalog


def get_cve_kev_info(cve_id):
    """Lookup a CVE in the CISA KEV catalog. Returns dict or None."""
    if not cve_id:
        return None
    catalog = load_cisa_kev()
    return catalog.get(cve_id.upper())


# ============================================================
#  Onda 7 — Spamhaus DROP / EDROP (no key, CIDR-based)
# ============================================================

def _parse_spamhaus_text(text):
    """Parse Spamhaus DROP-format lines: `CIDR ; SBL-id  ; comment`."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        head = line.split(';', 1)[0].strip()
        if not head:
            continue
        try:
            net = ipaddress.ip_network(head, strict=False)
        except ValueError:
            continue
        sbl = ''
        if ';' in line:
            rest = line.split(';', 1)[1].strip()
            sbl = rest.split()[0] if rest else ''
        out.append((net, sbl))
    return out


def load_spamhaus_drop():
    if _is_fresh('spamhaus_drop'):
        return _cache['spamhaus_drop']['data']
    text = _http_get(SPAMHAUS_DROP_URL)
    if text is None:
        return _cache['spamhaus_drop']['data']
    nets = _parse_spamhaus_text(text)
    _cache['spamhaus_drop'] = {'data': nets, 'updated': datetime.now()}
    print(f"[threat_intel] Spamhaus DROP loaded: {len(nets)} networks")
    return nets


def load_spamhaus_edrop():
    if _is_fresh('spamhaus_edrop'):
        return _cache['spamhaus_edrop']['data']
    text = _http_get(SPAMHAUS_EDROP_URL)
    if text is None:
        return _cache['spamhaus_edrop']['data']
    nets = _parse_spamhaus_text(text)
    _cache['spamhaus_edrop'] = {'data': nets, 'updated': datetime.now()}
    print(f"[threat_intel] Spamhaus EDROP loaded: {len(nets)} networks")
    return nets


def _match_cidr_list(ip_addr_obj, networks):
    """Return first (network, sbl_id) containing ip_addr_obj, or None."""
    for net, sbl in networks:
        if ip_addr_obj.version != net.version:
            continue
        if ip_addr_obj in net:
            return (net, sbl)
    return None


def check_spamhaus(ip):
    """Return dict {list, network, sbl_id} or None."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    hit = _match_cidr_list(ip_obj, load_spamhaus_drop())
    if hit:
        return {'list': 'DROP',  'network': str(hit[0]), 'sbl_id': hit[1]}
    hit = _match_cidr_list(ip_obj, load_spamhaus_edrop())
    if hit:
        return {'list': 'EDROP', 'network': str(hit[0]), 'sbl_id': hit[1]}
    return None


def preload_all_feeds():
    """Eagerly load all free feeds. Call once at startup or before a scan."""
    load_ipsum_list()
    load_tor_exit_nodes()
    load_feodo_ips()
    load_threatfox_iocs()
    load_urlhaus_urls()
    load_sslbl_ja3()
    load_cisa_kev()
    load_spamhaus_drop()
    load_spamhaus_edrop()


def preload_optional_feeds(settings=None):
    """Pull credentialed bulk feeds (MISP + TAXII). No-op without creds."""
    if settings is None:
        try:
            import json
            with open('data/settings.json', 'r', encoding='utf-8') as f:
                settings = json.load(f)
        except Exception:
            settings = {}
    consume_misp(settings)
    consume_taxii(settings)


# ============================================================
#  AbuseIPDB (optional)
# ============================================================

def check_abuseipdb(ip_address, settings=None):
    key = _get_key('abuseipdb', settings)
    if not key:
        return None
    try:
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': key, 'Accept': 'application/json'},
            params={'ipAddress': ip_address, 'maxAgeInDays': 90},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return {
                'abuse_confidence': data.get('abuseConfidenceScore', 0),
                'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                'total_reports': data.get('totalReports', 0),
                'last_seen': data.get('lastReportedAt'),
            }
        time.sleep(0.1)
    except Exception as e:
        print(f"[threat_intel] AbuseIPDB error for {ip_address}: {e}")
    return None


# ============================================================
#  Reputation lookups
# ============================================================

def get_ip_reputation(ip_address):
    """
    Combined IP reputation across all loaded feeds.
    Result schema (also persisted in DB):
      reputation_score : 0-100
      is_malicious     : bool
      abuse_confidence : 0-100 (AbuseIPDB only)
      sources          : list[str]
      last_seen        : str|None
      labels           : list[str]  (malware family / category tags)
    """
    cached = db.get_ip_reputation(ip_address)
    if cached:
        return cached

    sources = []
    labels = []
    score = 0
    is_malicious = False
    abuse_confidence = 0
    last_seen = None

    ipsum = load_ipsum_list()
    if ip_address in ipsum:
        sources.append('IPsum')
        score += min(ipsum[ip_address] * 15, 60)
        labels.append(f"ipsum:{ipsum[ip_address]}-lists")
        is_malicious = True

    tor = load_tor_exit_nodes()
    if ip_address in tor:
        sources.append('Tor')
        score += 25
        labels.append('tor-exit-node')

    feodo = load_feodo_ips()
    if ip_address in feodo:
        sources.append('Feodo')
        score += 80
        labels.append('feodo-c2')
        is_malicious = True

    tf = load_threatfox_iocs()
    if ip_address in tf['ips']:
        sources.append('ThreatFox')
        score += 80
        labels.append(f"threatfox:{tf['ips'][ip_address]['malware']}")
        is_malicious = True

    spam = check_spamhaus(ip_address)
    if spam:
        sources.append(f"Spamhaus {spam['list']}")
        score += 70
        labels.append(f"spamhaus-{spam['list'].lower()}:{spam['network']}")
        is_malicious = True

    otx_cache = _cache['otx']['ips']
    if ip_address in otx_cache:
        sources.append('OTX')
        score += 60
        labels.append(f"otx:{otx_cache[ip_address].get('pulse_count', 0)}-pulses")
        is_malicious = True

    misp_ips = _cache['misp']['ips']
    if ip_address in misp_ips:
        sources.append('MISP')
        score += 70
        labels.append(f"misp:{misp_ips[ip_address].get('event_info', 'event')}")
        is_malicious = True

    taxii_ips = _cache['taxii']['ips']
    if ip_address in taxii_ips:
        sources.append('TAXII')
        score += 70
        labels.append(f"taxii:{taxii_ips[ip_address].get('label', 'indicator')}")
        is_malicious = True

    abuse_data = check_abuseipdb(ip_address)
    if abuse_data:
        sources.append('AbuseIPDB')
        abuse_confidence = abuse_data['abuse_confidence']
        score += abuse_confidence
        is_malicious = is_malicious or abuse_data['is_malicious']
        last_seen = abuse_data.get('last_seen')

    score = min(score, 100)
    result = {
        'reputation_score': score,
        'is_malicious': is_malicious,
        'abuse_confidence': abuse_confidence,
        'sources': sources,
        'last_seen': last_seen,
        'labels': labels,
    }

    if sources or not ABUSEIPDB_API_KEY:
        try:
            db.save_ip_reputation(ip_address, result)
        except Exception as e:
            print(f"[threat_intel] cache write error for {ip_address}: {e}")

    return result


def get_domain_reputation(domain):
    """Lookup domain in ThreatFox + URLhaus. Returns dict or None."""
    if not domain:
        return None
    domain = domain.lower().strip('.')

    tf = load_threatfox_iocs()
    uh = load_urlhaus_urls()

    sources = []
    labels = []

    if domain in tf['domains']:
        sources.append('ThreatFox')
        labels.append(f"threatfox:{tf['domains'][domain]['malware']}")
    if domain in uh['hosts']:
        sources.append('URLhaus')
        entry = uh['hosts'][domain]
        labels.append(f"urlhaus:{entry.get('threat','')}")
    if domain in _cache['otx']['domains']:
        sources.append('OTX')
        labels.append(f"otx:{_cache['otx']['domains'][domain].get('pulse_count', 0)}-pulses")
    if domain in _cache['misp']['domains']:
        sources.append('MISP')
        labels.append(f"misp:{_cache['misp']['domains'][domain].get('event_info','event')}")
    if domain in _cache['taxii']['domains']:
        sources.append('TAXII')
        labels.append(f"taxii:{_cache['taxii']['domains'][domain].get('label','indicator')}")

    if not sources:
        return None
    return {
        'is_malicious': True,
        'sources': sources,
        'labels': labels,
    }


def get_ja3_reputation(ja3_md5):
    """Lookup JA3 fingerprint against SSLBL."""
    if not ja3_md5:
        return None
    sslbl = load_sslbl_ja3()
    md5 = ja3_md5.lower()
    if md5 in sslbl:
        return {'source': 'SSLBL', 'description': sslbl[md5]}
    return None


# ============================================================
#  Bulk enrichment helpers
# ============================================================

# ============================================================
#  Additional optional API services
# ============================================================

def check_virustotal(indicator, indicator_type='ip', settings=None):
    """VirusTotal v3 lookup for IP or domain. Returns summary dict or None."""
    key = _get_key('virustotal', settings)
    if not key:
        return None
    try:
        if indicator_type == 'ip':
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}'
        else:
            url = f'https://www.virustotal.com/api/v3/domains/{indicator}'
        resp = requests.get(url, headers={'x-apikey': key}, timeout=8)
        if resp.status_code == 200:
            attrs = resp.json().get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) or 1
            result = {
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_engines': total,
                'reputation': attrs.get('reputation', 0),
                'is_malicious': malicious > 0,
            }
            if indicator_type == 'ip':
                result['country'] = attrs.get('country', '')
                result['as_owner'] = attrs.get('as_owner', '')
                result['asn'] = attrs.get('asn')
            else:
                result['categories'] = attrs.get('categories', {})
            return result
        if resp.status_code == 404:
            return {'error': 'not found', 'is_malicious': False}
    except Exception as e:
        print(f"[threat_intel] VirusTotal error for {indicator}: {e}")
    return None


def check_shodan(ip, settings=None):
    """Shodan host lookup. Returns condensed host info or None."""
    key = _get_key('shodan', settings)
    if not key:
        return None
    try:
        resp = requests.get(
            f'https://api.shodan.io/shodan/host/{ip}',
            params={'key': key},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                'org': data.get('org', ''),
                'isp': data.get('isp', ''),
                'country': data.get('country_name', ''),
                'city': data.get('city', ''),
                'ports': data.get('ports', []),
                'tags': data.get('tags', []),
                'vulns': list((data.get('vulns') or {}).keys())[:10],
                'last_update': data.get('last_update', ''),
            }
        if resp.status_code == 404:
            return {'error': 'not found'}
    except Exception as e:
        print(f"[threat_intel] Shodan error for {ip}: {e}")
    return None


def check_greynoise(ip, settings=None):
    """GreyNoise community IP lookup. Returns classification or None."""
    key = _get_key('greynoise', settings)
    if not key:
        return None
    try:
        resp = requests.get(
            f'https://api.greynoise.io/v3/community/{ip}',
            headers={'key': key},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                'noise': data.get('noise', False),
                'riot': data.get('riot', False),
                'classification': data.get('classification', ''),
                'name': data.get('name', ''),
                'message': data.get('message', ''),
            }
        if resp.status_code in (404, 400):
            try:
                return {'message': resp.json().get('message', 'not found')}
            except Exception:
                return {'message': 'not found'}
    except Exception as e:
        print(f"[threat_intel] GreyNoise error for {ip}: {e}")
    return None


# ============================================================
#  Onda 7 — AlienVault OTX (free key)
# ============================================================

def _otx_call(path, settings=None):
    key = _get_key('otx', settings)
    if not key:
        return None
    try:
        resp = requests.get(
            f'https://otx.alienvault.com/api/v1/{path}',
            headers={'X-OTX-API-KEY': key},
            timeout=8,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"[threat_intel] OTX error on {path}: {e}")
    return None


def check_otx_ip(ip, settings=None):
    """OTX IPv4 lookup. Caches into _cache['otx']['ips'] when malicious."""
    data = _otx_call(f'indicators/IPv4/{ip}/general', settings)
    if not data:
        return None
    pulse_info = data.get('pulse_info') or {}
    count = pulse_info.get('count', 0)
    names = [p.get('name') for p in (pulse_info.get('pulses') or [])[:5]]
    summary = {
        'pulse_count': count,
        'pulse_names': [n for n in names if n],
        'country': data.get('country_name', ''),
        'asn': data.get('asn', ''),
        'is_malicious': count > 0,
    }
    if count > 0:
        _cache['otx']['ips'][ip] = summary
    return summary


def check_otx_domain(domain, settings=None):
    """OTX domain lookup. Caches into _cache['otx']['domains'] when malicious."""
    data = _otx_call(f'indicators/domain/{domain}/general', settings)
    if not data:
        return None
    pulse_info = data.get('pulse_info') or {}
    count = pulse_info.get('count', 0)
    summary = {
        'pulse_count': count,
        'pulse_names': [p.get('name') for p in (pulse_info.get('pulses') or [])[:5]],
        'is_malicious': count > 0,
    }
    if count > 0:
        _cache['otx']['domains'][domain.lower().strip('.')] = summary
    return summary


# ============================================================
#  Onda 7 — CIRCL Passive DNS / Passive SSL (basic auth)
# ============================================================

def _circl_auth(settings=None):
    """Return (user, password) tuple or None if not configured."""
    raw = _get_key('circl', settings)
    if not raw or ':' not in raw:
        # Also accept settings split form: circl_user / circl_password
        if settings:
            user = (settings.get('api_keys') or {}).get('circl_user', '')
            pw = (settings.get('api_keys') or {}).get('circl_password', '')
            if user and pw:
                return (user, pw)
        return None
    user, _, password = raw.partition(':')
    return (user, password) if user and password else None


def check_circl_pdns(rrname, settings=None):
    """CIRCL Passive DNS — historical resolutions for a domain.

    Returns list of {rdata, rrtype, time_first, time_last, count} or None.
    """
    auth = _circl_auth(settings)
    if not auth:
        return None
    try:
        resp = requests.get(
            f'https://www.circl.lu/pdns/query/{rrname}',
            auth=auth,
            headers={'Accept': 'application/json'},
            timeout=8,
        )
        if resp.status_code != 200:
            if resp.status_code in (401, 403):
                print(f"[threat_intel] CIRCL pDNS auth failed ({resp.status_code})")
            return None
        # CIRCL pDNS returns NDJSON (one JSON object per line).
        import json as _json
        entries = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(_json.loads(line))
            except Exception:
                continue
        return entries[:50]
    except Exception as e:
        print(f"[threat_intel] CIRCL pDNS error for {rrname}: {e}")
    return None


def check_circl_pssl(ip, settings=None):
    """CIRCL Passive SSL — certs seen at a given IP."""
    auth = _circl_auth(settings)
    if not auth:
        return None
    try:
        resp = requests.get(
            f'https://www.circl.lu/v2pssl/query/{ip}',
            auth=auth,
            headers={'Accept': 'application/json'},
            timeout=8,
        )
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception as e:
        print(f"[threat_intel] CIRCL pSSL error for {ip}: {e}")
    return None


# ============================================================
#  Onda 7 — MISP consumer (URL + key)
# ============================================================

# Recognized MISP attribute types we ingest.
_MISP_IP_TYPES     = {'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'}
_MISP_DOMAIN_TYPES = {'domain', 'hostname', 'domain|ip'}
_MISP_HASH_TYPES   = {'md5', 'sha1', 'sha256'}
_MISP_URL_TYPES    = {'url', 'uri'}


def consume_misp(settings=None):
    """Pull recent IOCs from a MISP instance into the per-process cache.

    Required settings (under settings['api_keys'] or settings root):
      - misp_url      e.g. https://misp.example.org
      - misp          (the auth key, also acceptable via env MISP_AUTH_KEY)
    Optional:
      - misp_last     time window string (default '30d')

    Silent no-op when either URL or key is missing.
    """
    if settings is None:
        settings = {}
    key = _get_key('misp', settings)
    url = ''
    if settings:
        url = (settings.get('api_keys') or {}).get('misp_url', '') \
              or settings.get('misp_url', '')
    if not url:
        url = os.environ.get('MISP_URL', '')
    if not url or not key:
        return None
    last = (settings.get('api_keys') or {}).get('misp_last', '') or '30d'
    body = {
        'returnFormat': 'json',
        'last': last,
        'type': list(_MISP_IP_TYPES | _MISP_DOMAIN_TYPES
                     | _MISP_HASH_TYPES | _MISP_URL_TYPES),
        'limit': 5000,
    }
    try:
        resp = requests.post(
            url.rstrip('/') + '/attributes/restSearch',
            headers={
                'Authorization': key,
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            json=body,
            timeout=30,
            verify=True,
        )
        if resp.status_code != 200:
            print(f"[threat_intel] MISP HTTP {resp.status_code}")
            return None
        payload = resp.json()
    except Exception as e:
        print(f"[threat_intel] MISP error: {e}")
        return None

    attrs = (payload.get('response') or {}).get('Attribute') or []
    out = {'ips': {}, 'domains': {}, 'hashes': {}, 'urls': {},
           'updated': datetime.now()}
    for a in attrs:
        atype = (a.get('type') or '').lower()
        value = a.get('value') or ''
        if not value:
            continue
        ev = a.get('Event') or {}
        meta = {
            'event_id':   ev.get('id', ''),
            'event_info': ev.get('info', ''),
            'category':   a.get('category', ''),
            'comment':    a.get('comment', ''),
            'source':     'MISP',
        }
        if atype in _MISP_IP_TYPES:
            ip_only = value.split('|')[0].split(':')[0]
            out['ips'][ip_only] = meta
        elif atype in _MISP_DOMAIN_TYPES:
            dom = value.split('|')[0].lower().strip('.')
            if dom:
                out['domains'][dom] = meta
        elif atype in _MISP_HASH_TYPES:
            out['hashes'][value.lower()] = meta
        elif atype in _MISP_URL_TYPES:
            out['urls'][value] = meta
    _cache['misp'] = out
    print(f"[threat_intel] MISP loaded: {len(out['ips'])} IPs / "
          f"{len(out['domains'])} domains / {len(out['hashes'])} hashes")
    return out


# ============================================================
#  Onda 7 — TAXII 2.1 consumer (URL + creds)
# ============================================================

# Crude STIX pattern parser — pulls indicator values from string patterns like:
#   [ipv4-addr:value = '1.2.3.4']
#   [domain-name:value = 'evil.example']
#   [file:hashes.'SHA-256' = '<hex>']
_STIX_PAT_IP     = re.compile(
    r"(?:ipv4-addr|ipv6-addr):value\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_STIX_PAT_DOMAIN = re.compile(
    r"domain-name:value\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_STIX_PAT_HASH   = re.compile(
    r"file:hashes\.'?(?:MD5|SHA-1|SHA-256|SHA1|SHA256)'?\s*=\s*['\"]([0-9a-fA-F]+)['\"]",
    re.IGNORECASE,
)


def consume_taxii(settings=None):
    """Pull STIX 2.1 indicators from a TAXII collection.

    Required settings (under settings['api_keys'] or settings root):
      - taxii_url        full collection objects URL OR base + collection id
      - taxii_collection collection id (if taxii_url is the API root)
      - taxii            "user:password" (or env TAXII_AUTH)
    Silent no-op when URL or creds are missing.
    """
    if settings is None:
        settings = {}
    raw_auth = _get_key('taxii', settings)
    if raw_auth:
        if ':' not in raw_auth:
            print('[threat_intel] TAXII auth must be "user:password"')
            return None
        t_user, _, t_pass = raw_auth.partition(':')
    else:
        keys = settings.get('api_keys') or {}
        t_user = keys.get('taxii_user', '')
        t_pass = keys.get('taxii_password', '')
        if not (t_user and t_pass):
            return None

    keys = settings.get('api_keys') or {}
    base_url = keys.get('taxii_url', '') or settings.get('taxii_url', '') \
               or os.environ.get('TAXII_URL', '')
    collection = keys.get('taxii_collection', '') \
                 or settings.get('taxii_collection', '') \
                 or os.environ.get('TAXII_COLLECTION', '')
    if not base_url:
        return None

    if '/collections/' in base_url and base_url.rstrip('/').endswith('objects'):
        objects_url = base_url
    elif collection:
        objects_url = f"{base_url.rstrip('/')}/collections/{collection}/objects/"
    else:
        objects_url = base_url.rstrip('/') + '/objects/'

    try:
        resp = requests.get(
            objects_url,
            auth=(t_user, t_pass),
            headers={'Accept': 'application/taxii+json;version=2.1'},
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"[threat_intel] TAXII HTTP {resp.status_code}")
            return None
        payload = resp.json()
    except Exception as e:
        print(f"[threat_intel] TAXII error: {e}")
        return None

    out = {'ips': {}, 'domains': {}, 'hashes': {}, 'updated': datetime.now()}
    objects = payload.get('objects') or []
    for obj in objects:
        if obj.get('type') != 'indicator':
            continue
        pattern = obj.get('pattern') or ''
        label = (obj.get('labels') or ['indicator'])[0]
        meta = {
            'label':       label,
            'name':        obj.get('name', ''),
            'description': obj.get('description', ''),
            'created':     obj.get('created', ''),
            'source':      'TAXII',
        }
        for m in _STIX_PAT_IP.finditer(pattern):
            out['ips'][m.group(1)] = meta
        for m in _STIX_PAT_DOMAIN.finditer(pattern):
            out['domains'][m.group(1).lower().strip('.')] = meta
        for m in _STIX_PAT_HASH.finditer(pattern):
            out['hashes'][m.group(1).lower()] = meta
    _cache['taxii'] = out
    print(f"[threat_intel] TAXII loaded: {len(out['ips'])} IPs / "
          f"{len(out['domains'])} domains / {len(out['hashes'])} hashes")
    return out


def manual_lookup(indicator, indicator_type, settings=None):
    """
    Aggregate threat intel lookup for a single IP or domain.
    Queries all configured free feeds + API-key services.
    Returns a structured result dict.
    """
    result = {
        'indicator': indicator,
        'type': indicator_type,
        'sources': {},
        'summary': {
            'is_malicious': False,
            'reputation_score': 0,
            'labels': [],
        },
    }
    score = 0
    is_malicious = False
    labels = []

    if indicator_type == 'ip':
        ipsum = load_ipsum_list()
        if indicator in ipsum:
            s = ipsum[indicator]
            result['sources']['ipsum'] = {'lists': s, 'label': f"listed in {s} blocklists"}
            score += min(s * 15, 60)
            is_malicious = True
            labels.append(f"ipsum:{s}-lists")

        tor = load_tor_exit_nodes()
        if indicator in tor:
            result['sources']['tor'] = {'is_exit_node': True}
            score += 25
            labels.append('tor-exit-node')

        feodo = load_feodo_ips()
        if indicator in feodo:
            result['sources']['feodo'] = {'malware': feodo[indicator]}
            score += 80
            is_malicious = True
            labels.append('feodo-c2')

        tf = load_threatfox_iocs()
        if indicator in tf['ips']:
            result['sources']['threatfox'] = tf['ips'][indicator]
            score += 80
            is_malicious = True
            labels.append(f"threatfox:{tf['ips'][indicator].get('malware','')}")

        abuse = check_abuseipdb(indicator, settings)
        if abuse:
            result['sources']['abuseipdb'] = abuse
            score += abuse.get('abuse_confidence', 0)
            if abuse.get('is_malicious'):
                is_malicious = True

        vt = check_virustotal(indicator, 'ip', settings)
        if vt:
            result['sources']['virustotal'] = vt
            if vt.get('is_malicious'):
                is_malicious = True
                labels.append('virustotal-malicious')

        sh = check_shodan(indicator, settings)
        if sh:
            result['sources']['shodan'] = sh

        gn = check_greynoise(indicator, settings)
        if gn:
            result['sources']['greynoise'] = gn
            if gn.get('classification') == 'malicious':
                is_malicious = True
                labels.append('greynoise-malicious')

        spam = check_spamhaus(indicator)
        if spam:
            result['sources']['spamhaus'] = spam
            score += 70
            is_malicious = True
            labels.append(f"spamhaus-{spam['list'].lower()}")

        otx = check_otx_ip(indicator, settings)
        if otx:
            result['sources']['otx'] = otx
            if otx.get('is_malicious'):
                score += 60
                is_malicious = True
                labels.append(f"otx:{otx.get('pulse_count', 0)}-pulses")

        pssl = check_circl_pssl(indicator, settings)
        if pssl is not None:
            result['sources']['circl_pssl'] = pssl

        if indicator in _cache['misp']['ips']:
            result['sources']['misp'] = _cache['misp']['ips'][indicator]
            score += 70
            is_malicious = True
            labels.append('misp')
        if indicator in _cache['taxii']['ips']:
            result['sources']['taxii'] = _cache['taxii']['ips'][indicator]
            score += 70
            is_malicious = True
            labels.append('taxii')

    elif indicator_type == 'domain':
        domain_lower = indicator.lower().strip('.')
        tf = load_threatfox_iocs()
        if domain_lower in tf['domains']:
            result['sources']['threatfox'] = tf['domains'][domain_lower]
            score += 80
            is_malicious = True
            labels.append(f"threatfox:{tf['domains'][domain_lower].get('malware','')}")

        uh = load_urlhaus_urls()
        if domain_lower in uh['hosts']:
            result['sources']['urlhaus'] = uh['hosts'][domain_lower]
            score += 60
            is_malicious = True
            labels.append('urlhaus')

        vt = check_virustotal(indicator, 'domain', settings)
        if vt:
            result['sources']['virustotal'] = vt
            if vt.get('is_malicious'):
                is_malicious = True
                labels.append('virustotal-malicious')

        otx = check_otx_domain(indicator, settings)
        if otx:
            result['sources']['otx'] = otx
            if otx.get('is_malicious'):
                score += 60
                is_malicious = True
                labels.append(f"otx:{otx.get('pulse_count', 0)}-pulses")

        pdns = check_circl_pdns(indicator, settings)
        if pdns is not None:
            result['sources']['circl_pdns'] = pdns

        if domain_lower in _cache['misp']['domains']:
            result['sources']['misp'] = _cache['misp']['domains'][domain_lower]
            score += 70
            is_malicious = True
            labels.append('misp')
        if domain_lower in _cache['taxii']['domains']:
            result['sources']['taxii'] = _cache['taxii']['domains'][domain_lower]
            score += 70
            is_malicious = True
            labels.append('taxii')

    result['summary']['reputation_score'] = min(score, 100)
    result['summary']['is_malicious'] = is_malicious
    result['summary']['labels'] = labels
    return result


SERVICE_SUBFIELDS = {
    'circl': [
        {'id': 'circl_user',     'label': 'Usuário',        'secret': False,
         'placeholder': 'user@example.org'},
        {'id': 'circl_password', 'label': 'Senha',          'secret': True,
         'placeholder': 'Senha do CIRCL'},
    ],
    'misp': [
        {'id': 'misp_url', 'label': 'URL',     'secret': False,
         'placeholder': 'https://misp.example.org'},
        {'id': 'misp',     'label': 'Auth Key', 'secret': True,
         'placeholder': 'Cole a auth key MISP'},
    ],
    'taxii': [
        {'id': 'taxii_url',        'label': 'URL',        'secret': False,
         'placeholder': 'https://server/taxii2/api1'},
        {'id': 'taxii_collection', 'label': 'Collection', 'secret': False,
         'placeholder': 'collection-id (uuid)'},
        {'id': 'taxii',            'label': 'Basic Auth', 'secret': True,
         'placeholder': 'user:password'},
    ],
}


def _subfield_value(field_id, settings):
    """Return saved value for a subfield, or empty string. Only safe for non-secret fields."""
    if not settings:
        return ''
    return (settings.get('api_keys') or {}).get(field_id, '') or settings.get(field_id, '') or ''


def _attach_subfields(entry, settings):
    """Decorate a service entry with subfields, including current values for non-secret ones."""
    raw = SERVICE_SUBFIELDS.get(entry['id'])
    if raw is None:
        return entry
    fields = []
    for f in raw:
        out = dict(f)
        if not f['secret']:
            out['current_value'] = _subfield_value(f['id'], settings)
        out['configured'] = bool(_subfield_value(f['id'], settings)) if not f['secret'] \
                            else bool(_get_key(f['id'], settings))
        fields.append(out)
    entry['subfields'] = fields
    return entry


def list_configured_services(settings=None):
    """Return metadata about all threat intel services and whether they are configured."""
    services = [
        {
            'id': 'ipsum',
            'name': 'IPsum',
            'description': 'IP blocklist aggregator (free, no key)',
            'requires_key': False,
            'configured': True,
            'types': ['ip'],
        },
        {
            'id': 'tor',
            'name': 'Tor Exit Nodes',
            'description': 'Tor Project exit node list (free, no key)',
            'requires_key': False,
            'configured': True,
            'types': ['ip'],
        },
        {
            'id': 'feodo',
            'name': 'Feodo Tracker',
            'description': 'Botnet C2 IP blocklist by abuse.ch (free, no key)',
            'requires_key': False,
            'configured': True,
            'types': ['ip'],
        },
        {
            'id': 'threatfox',
            'name': 'ThreatFox',
            'description': 'Multi-IOC feed by abuse.ch (free, no key)',
            'requires_key': False,
            'configured': True,
            'types': ['ip', 'domain'],
        },
        {
            'id': 'urlhaus',
            'name': 'URLhaus',
            'description': 'Malicious URL / host feed by abuse.ch (free, no key)',
            'requires_key': False,
            'configured': True,
            'types': ['domain'],
        },
        {
            'id': 'abuseipdb',
            'name': 'AbuseIPDB',
            'description': 'IP abuse reports (free API key required)',
            'requires_key': True,
            'configured': bool(_get_key('abuseipdb', settings)),
            'types': ['ip'],
        },
        {
            'id': 'virustotal',
            'name': 'VirusTotal',
            'description': 'Multi-engine IP / domain / file-hash reputation (free API key required)',
            'requires_key': True,
            'configured': bool(_get_key('virustotal', settings)),
            'types': ['ip', 'domain', 'hash'],
        },
        {
            'id': 'shodan',
            'name': 'Shodan',
            'description': 'Internet-facing service fingerprinting (API key required)',
            'requires_key': True,
            'configured': bool(_get_key('shodan', settings)),
            'types': ['ip'],
        },
        {
            'id': 'greynoise',
            'name': 'GreyNoise',
            'description': 'Internet noise classification (API key required)',
            'requires_key': True,
            'configured': bool(_get_key('greynoise', settings)),
            'types': ['ip'],
        },
        {
            'id': 'malwarebazaar',
            'name': 'MalwareBazaar',
            'description': 'File hash lookup by abuse.ch (free, key optional)',
            'requires_key': False,
            'configured': True,
            'types': ['hash'],
        },
        {
            'id': 'cisa_kev',
            'name': 'CISA KEV',
            'description': 'Known Exploited Vulnerabilities catalog (free, no key)',
            'requires_key': False,
            'configured': True,
            'types': ['cve'],
        },
        {
            'id': 'spamhaus',
            'name': 'Spamhaus DROP/EDROP',
            'description': 'Hijacked / never-allocated CIDR blocks (free, no key)',
            'requires_key': False,
            'configured': True,
            'types': ['ip'],
        },
        {
            'id': 'otx',
            'name': 'AlienVault OTX',
            'description': 'Open Threat Exchange pulses (free API key required)',
            'requires_key': True,
            'configured': bool(_get_key('otx', settings)),
            'types': ['ip', 'domain', 'hash'],
        },
        {
            'id': 'circl',
            'name': 'CIRCL Passive DNS / SSL',
            'description': 'CIRCL historical pDNS / pSSL (basic auth — user:password)',
            'requires_key': True,
            'configured': bool(_circl_auth(settings)),
            'types': ['ip', 'domain'],
        },
        {
            'id': 'misp',
            'name': 'MISP',
            'description': 'MISP attribute consumer (URL + auth key)',
            'requires_key': True,
            'configured': bool(
                _get_key('misp', settings) and (
                    (settings or {}).get('api_keys', {}).get('misp_url', '')
                    or os.environ.get('MISP_URL', '')
                )
            ),
            'types': ['ip', 'domain', 'hash'],
        },
        {
            'id': 'taxii',
            'name': 'TAXII 2.1',
            'description': 'STIX 2.1 indicator collection (URL + basic auth)',
            'requires_key': True,
            'configured': bool(
                _get_key('taxii', settings) and (
                    (settings or {}).get('api_keys', {}).get('taxii_url', '')
                    or os.environ.get('TAXII_URL', '')
                )
            ),
            'types': ['ip', 'domain', 'hash'],
        },
    ]
    return [_attach_subfields(s, settings) for s in services]


def enrich_ips_with_reputation(results):
    """Tag external IPs in scan results with reputation data."""
    for ip_data in results.get('ips', []):
        if ip_data.get('is_local', True):
            continue
        try:
            ip_data['reputation'] = get_ip_reputation(ip_data['ip'])
        except Exception as e:
            print(f"[threat_intel] reputation error for {ip_data.get('ip')}: {e}")
    return results


def enrich_domains_in_alerts(results):
    """
    Walk DNS / TLS / HTTP related alerts and attach domain reputation when matched.
    Mutates `results['alerts']` in place.
    """
    domain_keys = ('domain', 'host', 'sni', 'qname', 'query')
    for alert in results.get('alerts', []):
        details = alert.get('details') or {}
        domains_to_check = set()
        for k in domain_keys:
            v = details.get(k)
            if isinstance(v, str):
                domains_to_check.add(v)
        # samples list of dicts (HTTP injection / exploit alerts)
        for sample in details.get('samples', []) or []:
            if isinstance(sample, dict):
                for k in domain_keys:
                    v = sample.get(k)
                    if isinstance(v, str):
                        domains_to_check.add(v)
        rep_hits = []
        for d in domains_to_check:
            rep = get_domain_reputation(d)
            if rep:
                rep_hits.append({'domain': d, **rep})
        if rep_hits:
            details['domain_reputation'] = rep_hits
            alert['details'] = details
    return results
