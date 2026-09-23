"""
Database module for PCAP Network Analyzer
Manages PostgreSQL database for storing scan history, IP names and geolocation
"""

import calendar
import hashlib
import threading
import psycopg2
import psycopg2.extras
from psycopg2 import pool as pg_pool
import json
import os
import shutil
import time
from datetime import datetime, timedelta, date, timezone
from contextlib import contextmanager
import ipaddress

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://pcap_user:pcap_pass@localhost:5432/pcap_analyzer')


def init_database():
    """Initialize database and create tables if they don't exist"""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Table for scans (captures)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                filename TEXT NOT NULL,
                analyzed_at TIMESTAMPTZ DEFAULT NOW(),
                packet_count INTEGER DEFAULT 0,
                total_bytes BIGINT DEFAULT 0,
                duration REAL DEFAULT 0,
                start_time TEXT,
                end_time TEXT,
                ip_count INTEGER DEFAULT 0,
                protocol_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0,
                results_json TEXT
            )
        ''')

        # Table for IP names (user-defined names for known hosts)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_names (
                id SERIAL PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                device_type TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')
        # Migration: add device_type column to legacy DBs
        cursor.execute("""
            ALTER TABLE ip_names
            ADD COLUMN IF NOT EXISTS device_type TEXT
        """)

        # Table for IP statistics per scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_stats (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                is_local BOOLEAN DEFAULT FALSE,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                bytes_sent BIGINT DEFAULT 0,
                bytes_received BIGINT DEFAULT 0,
                protocols TEXT,
                ports TEXT,
                alert_count INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for alerts per scan — partitioned by alert_date (monthly).
        # On a fresh DB this creates a proper partitioned table. On a legacy
        # non-partitioned DB we leave the table untouched and only add missing
        # columns (partitioning requires a DROP+recreate; use reset_db.py).
        cursor.execute("""
            SELECT c.relkind
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'alerts' AND n.nspname = 'public'
        """)
        row = cursor.fetchone()
        if row is None:
            # Fresh database — create as partitioned table
            cursor.execute('''
                CREATE TABLE alerts (
                    id BIGSERIAL NOT NULL,
                    alert_date DATE NOT NULL DEFAULT CURRENT_DATE,
                    scan_id INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    ip_address TEXT,
                    details TEXT,
                    recommendation TEXT,
                    timestamp TEXT,
                    triage_status TEXT NOT NULL DEFAULT 'analisar',
                    triage_note TEXT,
                    triage_assignee TEXT,
                    triaged_at TIMESTAMPTZ,
                    suppressed_by_rule INTEGER,
                    PRIMARY KEY (id, alert_date),
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                ) PARTITION BY RANGE (alert_date)
            ''')
            # Default partition catches overflow rows with dates outside monthly ranges
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts_default
                PARTITION OF alerts DEFAULT
            ''')
            _ensure_month_partition(cursor, datetime.now().date())
        else:
            # Legacy non-partitioned table — add missing columns only
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='alerts' AND column_name='triage_status'
                    ) THEN
                        ALTER TABLE alerts ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'analisar';
                        ALTER TABLE alerts ADD COLUMN triage_note TEXT;
                        ALTER TABLE alerts ADD COLUMN triage_assignee TEXT;
                        ALTER TABLE alerts ADD COLUMN triaged_at TIMESTAMPTZ;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='alerts' AND column_name='suppressed_by_rule'
                    ) THEN
                        ALTER TABLE alerts ADD COLUMN suppressed_by_rule INTEGER;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='alerts' AND column_name='alert_date'
                    ) THEN
                        ALTER TABLE alerts ADD COLUMN alert_date DATE DEFAULT CURRENT_DATE;
                    END IF;
                END $$;
            """)

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_scan ON alerts(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_triage ON alerts(triage_status)')

        # Triage vocabulary migration. The triage state machine was originally
        # (new, investigating, false_positive, confirmed). It is now a fixed
        # 4-category scheme: analisar (default), falso_positivo (user-marked
        # false positive — the training signal), resolvido, sem_risco
        # (auto-marked by the learned false-positive classifier). This UPDATE
        # only touches rows still carrying the legacy values, so it is a no-op
        # on an already-migrated DB.
        cursor.execute("""
            UPDATE alerts SET triage_status = CASE triage_status
                WHEN 'new'           THEN 'analisar'
                WHEN 'investigating' THEN 'analisar'
                WHEN 'false_positive' THEN 'falso_positivo'
                WHEN 'confirmed'     THEN 'resolvido'
                ELSE triage_status
            END
            WHERE triage_status IN ('new', 'investigating', 'false_positive', 'confirmed')
        """)
        cursor.execute("ALTER TABLE alerts ALTER COLUMN triage_status SET DEFAULT 'analisar'")

        # Whitelist / suppression rules: each row encodes "alerts matching
        # these criteria are known false-positives". Match semantics are AND
        # across non-null fields; null fields = wildcard.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suppression_rules (
                id SERIAL PRIMARY KEY,
                title_pattern TEXT,
                category TEXT,
                src_ip TEXT,
                src_cidr TEXT,
                reason TEXT,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                hit_count INTEGER NOT NULL DEFAULT 0
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_suppression_enabled ON suppression_rules(enabled)')
        # Later additions (idempotent) — the base table above predates
        # destination-side matching and rule attribution. CREATE TABLE IF NOT
        # EXISTS never adds columns to an existing table, so migrate here.
        cursor.execute('ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS dst_ip TEXT')
        cursor.execute('ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS dst_cidr TEXT')
        cursor.execute('ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS created_by TEXT')

        # Learned false-positive signatures. Every time an analyst marks an
        # alert as 'falso_positivo' we record a signature of that alert here.
        # On subsequent scans, any alert matching a signature is auto-filed as
        # 'sem_risco' instead of 'analisar' — the alert is still generated and
        # stored, it just doesn't count towards the "needs attention" badge.
        # Signature granularity: category + title + exact source IP.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fp_signatures (
                id SERIAL PRIMARY KEY,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                ip_address TEXT,
                match_count INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_matched_at TIMESTAMPTZ
            )
        ''')
        # Unique per (category, title, ip) — COALESCE so rows with no IP
        # still dedupe instead of being treated as distinct by NULL semantics.
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_signatures_uniq
            ON fp_signatures (category, title, COALESCE(ip_address, ''))
        ''')

        # Audit log — every state-changing request lands here. user_id is
        # left null until auth/RBAC ships; we keep the column so the schema
        # doesn't need a migration when it does.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                user_id TEXT,
                actor_ip TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT,
                target_type TEXT,
                target_id TEXT,
                status_code INTEGER,
                extra TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_log_occurred ON audit_log(occurred_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id)')
        # Tamper-evident hash chain (idempotent). Each row commits to the row
        # before it: row_hash = sha256(prev_hash || canonical(this row)). An
        # attacker with DB access who deletes or edits the row that recorded
        # their suppression-rule creation breaks the chain at that point, which
        # verify_audit_chain() detects. See write_audit / verify_audit_chain.
        cursor.execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT')
        cursor.execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS row_hash TEXT')

        # Outbound notification endpoints (Slack/Teams webhooks, generic
        # HTTP POST, Syslog CEF, SMTP). One row per channel; we filter
        # alerts by severity floor and optional category list.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhooks (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                min_severity TEXT NOT NULL DEFAULT 'high',
                categories TEXT,
                extra TEXT,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_used_at TIMESTAMPTZ,
                last_error TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled)')

        # Users / RBAC. Roles: viewer (read-only), analyst (mutations), admin
        # (everything + user mgmt). Password is werkzeug pbkdf2:sha256 hash.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login_at TIMESTAMPTZ,
                must_change_password BOOLEAN NOT NULL DEFAULT FALSE
            )
        ''')
        # TOTP second factor (idempotent). totp_secret holds the base32 seed;
        # totp_enabled flips to TRUE only after the user proves possession by
        # entering a valid code during enrollment. A pending (secret set,
        # enabled FALSE) enrollment is never accepted for step-up.
        cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT')
        cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE')

        # Table for protocol stats per scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_stats (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                packets INTEGER DEFAULT 0,
                bytes BIGINT DEFAULT 0,
                percentage REAL DEFAULT 0,
                risk_level TEXT,
                warning TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for protocol-IP statistics (IPs per protocol with stats)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_ip_stats (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                protocol_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                packets INTEGER DEFAULT 0,
                bytes BIGINT DEFAULT 0,
                is_local BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for IP geolocation cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_geolocation (
                id SERIAL PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                country TEXT,
                country_code TEXT,
                city TEXT,
                region TEXT,
                lat REAL,
                lon REAL,
                isp TEXT,
                cached_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')

        # Table for first-seen / last-seen artifact tracking. Powers the
        # correlation layer's "new artifact appeared on the network" alerts
        # (JA3, JA3S, SNI, HTTP host, MAC). Per (artifact_type, value).
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS artifact_seen (
                id SERIAL PRIMARY KEY,
                artifact_type TEXT NOT NULL,
                artifact_value TEXT NOT NULL,
                first_seen_at TIMESTAMPTZ NOT NULL,
                last_seen_at TIMESTAMPTZ NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 1,
                last_scan_id INTEGER,
                UNIQUE(artifact_type, artifact_value)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_artifact_seen_type ON artifact_seen(artifact_type)')

        # Asset inventory: per-MAC passive fingerprint accumulated across scans.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,
                mac_address TEXT UNIQUE NOT NULL,
                ip_addresses TEXT,
                os_guess TEXT,
                ttl_initial INTEGER,
                ttl_observed INTEGER,
                dhcp_vendor TEXT,
                dhcp_hostname TEXT,
                dhcp_param_list_hash TEXT,
                first_seen_at TIMESTAMPTZ NOT NULL,
                last_seen_at TIMESTAMPTZ NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 1,
                last_scan_id INTEGER
            )
        ''')

        # Table for IP reputation cache (threat intelligence)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id SERIAL PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                reputation_score INTEGER DEFAULT 0,
                is_malicious BOOLEAN DEFAULT FALSE,
                abuse_confidence INTEGER DEFAULT 0,
                sources TEXT,
                last_seen TEXT,
                cached_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')

        # Files carved out of HTTP flows + their reputation lookup. Per scan
        # so the UI can drill in by scan, but unique by sha256 within a scan
        # so duplicate downloads aren't double-counted.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS carved_files (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                sha256 TEXT NOT NULL,
                sha1 TEXT,
                md5 TEXT,
                filename TEXT,
                content_type TEXT,
                size_bytes BIGINT,
                source_url TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                direction TEXT,
                family TEXT,
                on_disk_path TEXT,
                malicious BOOLEAN DEFAULT FALSE,
                labels TEXT,
                vt_data JSONB,
                mb_data JSONB,
                looked_up_at TIMESTAMPTZ,
                yara_matches JSONB,
                yara_severity TEXT,
                yara_scanned_at TIMESTAMPTZ,
                carved_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(scan_id, sha256)
            )
        ''')

        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_scan ON ip_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_ip ON ip_stats(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_stats_scan ON protocol_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_ip_stats_scan ON protocol_ip_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_ip_stats_proto ON protocol_ip_stats(protocol_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_analyzed_at ON scans(analyzed_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_geolocation_ip ON ip_geolocation(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_reputation_ip ON ip_reputation(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_carved_files_scan ON carved_files(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_carved_files_sha256 ON carved_files(sha256)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_carved_files_malicious ON carved_files(malicious) WHERE malicious')

        # YARA columns — added after the initial release; only ALTER on legacy
        # DBs that pre-date them.
        cursor.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='carved_files' AND column_name='yara_matches'
                ) THEN
                    ALTER TABLE carved_files ADD COLUMN yara_matches JSONB;
                    ALTER TABLE carved_files ADD COLUMN yara_severity TEXT;
                    ALTER TABLE carved_files ADD COLUMN yara_scanned_at TIMESTAMPTZ;
                END IF;
            END $$;
        """)

        # Machines: one row per MAC (or per user-created "manual" host), with
        # the name the network announced (discovered_name, app-controlled) and
        # the name the user sees and edits (name). See pcap_analyzer/hosts.py.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id SERIAL PRIMARY KEY,
                host_key TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                is_manual BOOLEAN NOT NULL DEFAULT FALSE,
                discovered_name TEXT,
                discovered_name_previous TEXT,
                discovered_name_changed_at TIMESTAMPTZ,
                name TEXT,
                name_edited BOOLEAN NOT NULL DEFAULT FALSE,
                description TEXT,
                device_type TEXT,
                first_seen_at TIMESTAMPTZ,
                last_seen_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')
        # IP <-> machine bindings. source='auto' rows come from captures;
        # 'manual' rows are user decisions. excluded=TRUE records that the
        # user removed an automatic binding, so later scans don't re-add it.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_ips (
                id SERIAL PRIMARY KEY,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                ip_address TEXT NOT NULL,
                family SMALLINT,
                scope TEXT,
                source TEXT NOT NULL DEFAULT 'auto',
                excluded BOOLEAN NOT NULL DEFAULT FALSE,
                first_seen_at TIMESTAMPTZ,
                last_seen_at TIMESTAMPTZ,
                created_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE (host_id, ip_address)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_ips_ip ON host_ips(ip_address)')

        conn.commit()


def _ensure_month_partition(cursor, dt):
    """Create the monthly alerts partition for *dt* if it does not exist yet.

    Partition name: alerts_YYYY_MM  (e.g. alerts_2026_05)
    Range:          [first_of_month, first_of_next_month)
    Safe to call multiple times — uses IF NOT EXISTS.
    """
    if isinstance(dt, datetime):
        dt = dt.date()
    year, month = dt.year, dt.month
    partition_name = f"alerts_{year}_{month:02d}"
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    cursor.execute(
        f"CREATE TABLE IF NOT EXISTS {partition_name} "
        f"PARTITION OF alerts FOR VALUES FROM (%s) TO (%s)",
        (str(start), str(end)),
    )


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------
#
# Every request used to open a fresh psycopg2 connection and close it. The scan
# view alone fans out a dozen parallel AJAX calls, so that churn added latency
# and could exhaust Postgres' connection slots under load. A pool keeps a small
# set of warm connections instead.
#
# The pool is created lazily and keyed on the owning PID. psycopg2 connections
# cannot cross a fork: parent and child would share one socket and corrupt the
# protocol stream. database.py is imported — and init_database() runs — before
# Celery forks its workers (and, with a preloaded Gunicorn, before its workers
# fork), so a pool built at import time would be inherited. Rebuilding it
# whenever the PID changes makes each process get its own connections; Celery
# additionally calls reset_pool() from worker_process_init for an immediate,
# explicit reset (see celery_app.py).
#
# ThreadedConnectionPool is thread-safe — what Gunicorn's gthread worker needs.
# DB_POOL_MAX must be >= the number of concurrent DB users in a single process:
# GUNICORN_THREADS (default 8) for the web, or the Celery --concurrency for a
# worker. The default of 10 covers the bundled config; raise it in lockstep if
# you raise those. The pool only opens connections on demand (up to the max),
# so a generous ceiling costs nothing until it is actually needed.

_POOL_MIN = int(os.environ.get('DB_POOL_MIN', '1'))
_POOL_MAX = int(os.environ.get('DB_POOL_MAX', '10'))
_pool = None
_pool_pid = None
_pool_lock = threading.Lock()


def _get_pool():
    """Return this process's connection pool, rebuilding it after a fork."""
    global _pool, _pool_pid
    pid = os.getpid()
    pool = _pool
    if pool is not None and _pool_pid == pid:
        return pool
    with _pool_lock:
        if _pool is not None and _pool_pid == pid:
            return _pool
        # A pool reference inherited from a parent process is abandoned, not
        # closed: closing it would push protocol bytes over sockets the parent
        # still owns. The inherited fds are released when this process exits.
        _pool = pg_pool.ThreadedConnectionPool(
            _POOL_MIN, _POOL_MAX, DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        _pool_pid = pid
        return _pool


def reset_pool():
    """Forget the current pool so the next get_connection() builds a fresh one.

    Intended to run right after a fork (Celery's worker_process_init) so a child
    never borrows a connection inherited from its parent. The inherited pool
    object is dropped without closing it — see _get_pool()."""
    global _pool, _pool_pid
    with _pool_lock:
        _pool = None
        _pool_pid = None


@contextmanager
def get_connection():
    """Yield a pooled database connection, returning it to the pool on exit.

    On a clean exit the transaction is rolled back before the connection is
    recycled, so a read-only caller that never commits cannot leave it "idle in
    transaction" (holding a snapshot and locks) for the next borrower. Write
    paths still commit explicitly; a rollback after a commit is a no-op. A
    connection found dead — or one that fails to reset — is discarded rather
    than handed out again in a poisoned state.
    """
    pool = _get_pool()
    conn = pool.getconn()
    # A pooled connection can die while idle (server restart, network blip,
    # idle-in-transaction timeout). psycopg2 only flags this lazily, but when
    # it is already marked closed we can cheaply swap it for a fresh one.
    if conn.closed:
        pool.putconn(conn, close=True)
        conn = pool.getconn()
    try:
        yield conn
    finally:
        # Cleanup must never mask an exception raised by the caller's block.
        try:
            if conn.closed:
                pool.putconn(conn, close=True)
            else:
                try:
                    conn.rollback()
                except Exception:
                    pool.putconn(conn, close=True)
                else:
                    pool.putconn(conn)
        except Exception as cleanup_err:
            print(f"[database] connection return failed: {cleanup_err}")


# ==================== SCAN OPERATIONS ====================

def save_scan(results, filename):
    """
    Save a complete scan to the database
    Returns the scan_id
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        summary = results.get('summary', {})
        ips = results.get('ips', [])
        protocols = results.get('protocols', [])
        alerts = results.get('alerts', [])

        # Insert scan
        cursor.execute('''
            INSERT INTO scans (
                filename, analyzed_at, packet_count, total_bytes, duration,
                start_time, end_time, ip_count, protocol_count, alert_count,
                results_json
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            filename,
            summary.get('analyzed_at', datetime.now().isoformat()),
            summary.get('packet_count', 0),
            summary.get('total_bytes', 0),
            summary.get('duration', 0),
            summary.get('start_time'),
            summary.get('end_time'),
            len(ips),
            len(protocols),
            len(alerts),
            json.dumps(results)
        ))

        scan_id = cursor.fetchone()['id']

        # Insert IP stats — one round-trip via execute_values instead of one
        # INSERT per IP (captures with thousands of hosts paid that in latency).
        if ips:
            psycopg2.extras.execute_values(
                cursor,
                '''INSERT INTO ip_stats (
                    scan_id, ip_address, is_local, packets_sent, packets_received,
                    bytes_sent, bytes_received, protocols, ports, alert_count
                ) VALUES %s''',
                [(
                    scan_id,
                    ip_data.get('ip'),
                    ip_data.get('is_local', False),
                    ip_data.get('packets_sent', 0),
                    ip_data.get('packets_received', 0),
                    ip_data.get('bytes_sent', 0),
                    ip_data.get('bytes_received', 0),
                    json.dumps(ip_data.get('protocols', [])),
                    json.dumps(ip_data.get('ports', [])),
                    ip_data.get('alert_count', 0),
                ) for ip_data in ips],
            )

        # Derive alert_date from the scan's analyzed_at (used as partition key).
        analyzed_at_str = summary.get('analyzed_at', datetime.now().isoformat())
        try:
            alert_date = datetime.fromisoformat(analyzed_at_str[:10]).date()
        except (ValueError, TypeError):
            alert_date = datetime.now().date()
        # Ensure the monthly partition exists before inserting any alerts.
        _ensure_month_partition(cursor, alert_date)

        # Pre-fetch active suppression rules so we evaluate each alert in O(R)
        # without N round-trips to the DB.
        suppression_rules = []
        suppression_hits = {}
        # High-severity alerts that a rule hid this scan — surfaced out-of-band
        # after commit so silencing an important alert is itself loud.
        suppressed_high = []
        try:
            cursor.execute('''
                SELECT id, title_pattern, category, src_ip, src_cidr,
                       dst_ip, dst_cidr
                FROM suppression_rules WHERE enabled = TRUE
            ''')
            suppression_rules = [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            print(f"[database] suppression rule fetch failed: {e}")

        # Pre-fetch learned false-positive signatures (see fp_signatures table).
        fp_signatures = []
        fp_signature_hits = {}
        try:
            cursor.execute('SELECT id, category, title, ip_address FROM fp_signatures')
            fp_signatures = [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            print(f"[database] fp signature fetch failed: {e}")

        # Insert alerts. Each alert starts in 'analisar'; suppression rules and
        # learned FP signatures demote it to 'sem_risco' (auto-classified as
        # not worth attention). Only 'analisar' alerts count towards the badge.
        # The per-alert triage decision stays in Python; the DB write is a
        # single execute_values with RETURNING, whose rows come back in the
        # SAME order as the params list — so we can zip the ids straight back
        # onto the alert dicts (the notification dispatch right after save_scan
        # needs a stable id on every alert).
        analisar_count = 0
        alert_params = []
        for alert in alerts:
            matched_rule = None
            triage_status = 'analisar'
            if suppression_rules:
                matched_rule = evaluate_suppression(alert, suppression_rules)
                if matched_rule is not None:
                    triage_status = 'sem_risco'
                    suppression_hits[matched_rule] = suppression_hits.get(matched_rule, 0) + 1
                    if (alert.get('severity') or '').lower() in ('high', 'critical'):
                        suppressed_high.append({
                            'rule_id': matched_rule,
                            'severity': alert.get('severity'),
                            'category': alert.get('category'),
                            'title': alert.get('title'),
                            'ip': alert.get('ip'),
                        })
            if triage_status == 'analisar' and fp_signatures:
                matched_sig = evaluate_fp_signatures(alert, fp_signatures)
                if matched_sig is not None:
                    triage_status = 'sem_risco'
                    fp_signature_hits[matched_sig] = fp_signature_hits.get(matched_sig, 0) + 1
            if triage_status == 'analisar':
                analisar_count += 1
            alert_params.append((
                scan_id,
                alert_date,
                alert.get('severity'),
                alert.get('category'),
                alert.get('title'),
                alert.get('description'),
                alert.get('ip'),
                json.dumps(alert.get('details', {})),
                alert.get('recommendation'),
                alert.get('timestamp'),
                triage_status,
                matched_rule,
            ))
        if alert_params:
            inserted = psycopg2.extras.execute_values(
                cursor,
                '''INSERT INTO alerts (
                    scan_id, alert_date, severity, category, title, description,
                    ip_address, details, recommendation, timestamp,
                    triage_status, suppressed_by_rule
                ) VALUES %s RETURNING id''',
                alert_params,
                fetch=True,
            )
            for alert, row in zip(alerts, inserted):
                alert['id'] = row['id']

        # scans.alert_count tracks only alerts that still need attention
        # ('analisar') — alerts auto-filed as 'sem_risco' don't inflate the
        # red badge in the scan history list.
        cursor.execute(
            'UPDATE scans SET alert_count = %s WHERE id = %s',
            (analisar_count, scan_id),
        )

        # Insert protocol stats
        if protocols:
            psycopg2.extras.execute_values(
                cursor,
                '''INSERT INTO protocol_stats (
                    scan_id, name, packets, bytes, percentage, risk_level, warning
                ) VALUES %s''',
                [(
                    scan_id,
                    proto.get('name'),
                    proto.get('packets', 0),
                    proto.get('bytes', 0),
                    proto.get('percentage', 0),
                    proto.get('risk_level'),
                    proto.get('warning'),
                ) for proto in protocols],
            )

        # Insert protocol-IP stats — flatten the nested dict into one bulk
        # insert. This is the biggest of the four tables (protocol × IP), so
        # collapsing N round-trips here is the main win.
        protocol_ips = results.get('protocol_ips', {})
        proto_ip_params = [
            (
                scan_id,
                proto_name,
                ip_data.get('ip'),
                ip_data.get('packets', 0),
                ip_data.get('bytes', 0),
                ip_data.get('is_local', False),
            )
            for proto_name, ip_list in protocol_ips.items()
            for ip_data in ip_list
        ]
        if proto_ip_params:
            psycopg2.extras.execute_values(
                cursor,
                '''INSERT INTO protocol_ip_stats (
                    scan_id, protocol_name, ip_address, packets, bytes, is_local
                ) VALUES %s''',
                proto_ip_params,
            )

        conn.commit()

    # Persist observed artifacts (first-seen/last-seen tracking). Outside the
    # main transaction so a partial scan still saves; artifact tracking is
    # advisory metadata, not gating.
    scan_time = summary.get('analyzed_at') or datetime.now().isoformat()
    try:
        observed = results.get('observed_artifacts') or {}
        if observed:
            record_artifacts(scan_id, scan_time, observed)
    except Exception as e:
        print(f"[database] artifact recording failed: {e}")

    try:
        assets = results.get('assets') or {}
        if assets:
            record_assets(scan_id, scan_time, assets)
    except Exception as e:
        print(f"[database] asset recording failed: {e}")

    try:
        hosts = results.get('hosts') or []
        if hosts:
            record_hosts(scan_id, scan_time, hosts)
    except Exception as e:
        print(f"[database] host recording failed: {e}")

    try:
        if suppression_hits:
            increment_suppression_hits(suppression_hits)
    except Exception as e:
        print(f"[database] suppression hit-count update failed: {e}")

    # Out-of-band alarm: a suppression rule just hid one or more high/critical
    # alerts on this scan. Fanned out to the configured webhooks on a daemon
    # thread so the act of hiding is announced through a channel an intruder on
    # the host does not control. Lazy import avoids an import-time cycle
    # (notifications imports database at module load).
    try:
        if suppressed_high:
            import notifications
            notifications.dispatch_suppression_events(
                scan_id, summary.get('filename') or filename, suppressed_high)
    except Exception as e:
        print(f"[database] suppression notification failed: {e}")

    try:
        if fp_signature_hits:
            increment_fp_signature_hits(fp_signature_hits)
    except Exception as e:
        print(f"[database] fp signature hit-count update failed: {e}")

    try:
        carved = results.get('carved_files') or []
        if carved:
            save_carved_files(scan_id, carved)
    except Exception as e:
        print(f"[database] carved files insert failed: {e}")

    return scan_id


def get_all_scans(date_from=None, date_to=None):
    """Get list of all scans (summary only), optionally filtered by date range"""
    with get_connection() as conn:
        cursor = conn.cursor()

        query = '''
            SELECT id, filename, analyzed_at, packet_count, total_bytes,
                   duration, ip_count, protocol_count, alert_count, start_time
            FROM scans
        '''
        params = []
        conditions = []

        if date_from:
            conditions.append('analyzed_at >= %s')
            params.append(date_from)
        if date_to:
            conditions.append('analyzed_at <= %s')
            params.append(date_to + ' 23:59:59')

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY analyzed_at DESC'

        cursor.execute(query, params)

        scans = []
        for row in cursor.fetchall():
            analyzed_at = row['analyzed_at']
            if hasattr(analyzed_at, 'isoformat'):
                analyzed_at = analyzed_at.isoformat()
            scans.append({
                'id': row['id'],
                'filename': row['filename'],
                'analyzed_at': analyzed_at,
                'start_time': row['start_time'],
                'packet_count': row['packet_count'],
                'total_bytes': row['total_bytes'],
                'duration': row['duration'],
                'ip_count': row['ip_count'],
                'protocol_count': row['protocol_count'],
                'alert_count': row['alert_count']
            })

        return scans


def get_scan_by_id(scan_id):
    """Get full scan results by ID"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT results_json FROM scans WHERE id = %s', (scan_id,))
        row = cursor.fetchone()

        if row:
            return json.loads(row['results_json'])
        return None


def get_latest_scan_id():
    """Return the id of the most recently analyzed scan, or None if none exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id FROM scans ORDER BY analyzed_at DESC LIMIT 1'
        )
        row = cursor.fetchone()
        return row['id'] if row else None


def delete_scan(scan_id):
    """Delete a scan and all related data. Returns the filename if deleted, None otherwise."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT filename FROM scans WHERE id = %s', (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        filename = row['filename']
        cursor.execute('DELETE FROM scans WHERE id = %s', (scan_id,))
        conn.commit()
        return filename


def delete_multiple_scans(scan_ids):
    """Delete multiple scans and all related data. Returns list of filenames deleted."""
    if not scan_ids:
        return []
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT filename FROM scans WHERE id = ANY(%s)', (scan_ids,))
        filenames = [row['filename'] for row in cursor.fetchall()]
        cursor.execute('DELETE FROM scans WHERE id = ANY(%s)', (scan_ids,))
        conn.commit()
        return filenames


# ==================== IP NAME OPERATIONS ====================

DEVICE_TYPE_DEFAULT = 'Computador'
DEVICE_TYPES = (
    'Computador', 'Roteador', 'Impressora', 'IoT', 'Smartphone',
    'Servidor', 'Switch', 'NAS', 'Camera', 'TV/Streaming', 'Console', 'Virtual', 'Desconhecido'
)


def get_ip_name(ip_address):
    """Get the name for a specific IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name, description, device_type FROM ip_names WHERE ip_address = %s', (ip_address,))
        row = cursor.fetchone()

        if row:
            return {
                'name': row['name'],
                'description': row['description'],
                'device_type': row['device_type'] or DEVICE_TYPE_DEFAULT,
            }
        return None


def get_all_ip_names():
    """Get all IP names"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT ip_address, name, description, device_type FROM ip_names ORDER BY ip_address')

        ip_names = {}
        for row in cursor.fetchall():
            ip_names[row['ip_address']] = {
                'name': row['name'],
                'description': row['description'],
                'device_type': row['device_type'] or DEVICE_TYPE_DEFAULT,
            }

        return ip_names


def set_ip_name(ip_address, name, description=None, device_type=None):
    """Set or update the name for an IP"""
    if device_type and device_type not in DEVICE_TYPES:
        device_type = None
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ip_names (ip_address, name, description, device_type, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT(ip_address) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                device_type = COALESCE(EXCLUDED.device_type, ip_names.device_type),
                updated_at = NOW()
        ''', (ip_address, name, description, device_type))
        conn.commit()
        return True


def delete_ip_name(ip_address):
    """Delete the name for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ip_names WHERE ip_address = %s', (ip_address,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted


# ==================== HOSTS (machines: IPv4 + IPv6 by MAC) ====================
#
# A host is one machine. Discovered hosts are keyed by MAC; hosts the user
# creates by hand get a 'manual:<id>' key. Two names are kept:
#   discovered_name  what the network announced (DHCP/NetBIOS/LLMNR/mDNS) —
#                    maintained by the app, never shown as the main label
#   name             what the user sees; copied from discovered_name (or from
#                    a legacy per-IP label) the first time, then only changed
#                    by the user. When the network name later changes, the
#                    old one goes to discovered_name_previous so the UI can
#                    flag it instead of silently renaming the machine.

_UNSET = object()


def _epoch_to_dt(ts):
    try:
        v = float(ts)
    except (TypeError, ValueError):
        return None
    if v < 946684800:  # pre-2000: no plausible capture clock
        return None
    try:
        return datetime.fromtimestamp(v, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_scan_time(scan_time_iso):
    try:
        dt = datetime.fromisoformat(str(scan_time_iso))
    except (TypeError, ValueError):
        dt = datetime.now()
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def _host_row(row):
    d = dict(row)
    for key in ('discovered_name_changed_at', 'first_seen_at', 'last_seen_at',
                'created_at', 'updated_at'):
        if hasattr(d.get(key), 'isoformat'):
            d[key] = d[key].isoformat()
    # device_type stays None when unset so a per-IP label's type is not
    # overridden by a default; the UI shows 'Computador' in that case.
    d['display_name'] = d.get('name') or d.get('discovered_name') or ''
    d['name_changed_on_network'] = bool(d.get('discovered_name_previous'))
    ips = d.get('ips')
    if isinstance(ips, str):
        d['ips'] = json.loads(ips)
    elif ips is None:
        d['ips'] = []
    return d


_HOSTS_SELECT = '''
    SELECT h.*,
           COALESCE(json_agg(json_build_object(
               'ip', hi.ip_address, 'family', hi.family, 'scope', hi.scope,
               'source', hi.source, 'excluded', hi.excluded,
               'first_seen_at', hi.first_seen_at,
               'last_seen_at', hi.last_seen_at,
               'created_by', hi.created_by)
               ORDER BY hi.family, hi.ip_address)
               FILTER (WHERE hi.id IS NOT NULL), '[]') AS ips
    FROM hosts h
    LEFT JOIN host_ips hi ON hi.host_id = h.id
'''


def record_hosts(scan_id, scan_time_iso, hosts):  # noqa: ARG001 (scan_id kept for symmetry)
    """Upsert the hosts an analysis found (results['hosts']).

    * New MAC host: name = the user's legacy per-IP label for one of its
      addresses (IPv4 first) if any, else the discovered name.
    * Existing host: discovered_name is refreshed (old value kept in
      discovered_name_previous when it changes); name is filled only while
      empty, or replaced by a per-IP label while the user never edited it.
    * Automatic IP bindings are upserted; manual and user-excluded rows are
      never touched here.
    """
    if not hosts:
        return
    scan_dt = _parse_scan_time(scan_time_iso)
    ip_labels = get_all_ip_names()
    with get_connection() as conn:
        cursor = conn.cursor()
        for h in hosts:
            key = h.get('host_key')
            if not key:
                continue
            addrs = h.get('addresses') or []
            firsts = [d for d in (_epoch_to_dt(a.get('first_ts')) for a in addrs) if d]
            lasts = [d for d in (_epoch_to_dt(a.get('last_ts')) for a in addrs) if d]
            first_seen = min(firsts) if firsts else scan_dt
            last_seen = max(lasts) if lasts else scan_dt
            discovered = h.get('discovered_name')
            label = None
            for a in sorted(addrs, key=lambda a: (a.get('family') or 9, a['ip'])):
                info = ip_labels.get(a['ip'])
                if info and info.get('name'):
                    label = info
                    break

            cursor.execute('SELECT * FROM hosts WHERE host_key = %s FOR UPDATE', (key,))
            row = cursor.fetchone()
            if row is None:
                if h.get('manual'):
                    continue  # the user deleted this manual host meanwhile
                cursor.execute('''
                    INSERT INTO hosts (host_key, mac_address, is_manual,
                        discovered_name, name, name_edited, description,
                        device_type, first_seen_at, last_seen_at)
                    VALUES (%s, %s, FALSE, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                ''', (
                    key, h.get('mac'), discovered,
                    label['name'] if label else discovered,
                    bool(label),
                    label.get('description') if label else None,
                    label.get('device_type') if label else None,
                    first_seen, last_seen,
                ))
                host_id = cursor.fetchone()['id']
            else:
                host_id = row['id']
                sets = ['last_seen_at = GREATEST(COALESCE(last_seen_at, %s), %s)',
                        'first_seen_at = LEAST(COALESCE(first_seen_at, %s), %s)',
                        'updated_at = NOW()']
                params = [last_seen, last_seen, first_seen, first_seen]
                if discovered and discovered != row['discovered_name']:
                    if row['discovered_name']:
                        sets += ['discovered_name_previous = %s',
                                 'discovered_name_changed_at = NOW()']
                        params.append(row['discovered_name'])
                    sets.append('discovered_name = %s')
                    params.append(discovered)
                if not row['name_edited'] and label:
                    sets += ['name = %s', 'name_edited = TRUE',
                             'device_type = COALESCE(device_type, %s)',
                             'description = COALESCE(description, %s)']
                    params += [label['name'], label.get('device_type'),
                               label.get('description')]
                elif not row['name'] and discovered:
                    sets.append('name = %s')
                    params.append(discovered)
                params.append(host_id)
                cursor.execute(
                    f'UPDATE hosts SET {", ".join(sets)} WHERE id = %s', params)

            auto_rows = []
            for a in addrs:
                a_first = _epoch_to_dt(a.get('first_ts')) or scan_dt
                a_last = _epoch_to_dt(a.get('last_ts')) or scan_dt
                if a.get('binding') == 'manual':
                    cursor.execute('''
                        UPDATE host_ips SET
                            last_seen_at = GREATEST(COALESCE(last_seen_at, %s), %s),
                            first_seen_at = LEAST(COALESCE(first_seen_at, %s), %s)
                        WHERE host_id = %s AND ip_address = %s
                    ''', (a_last, a_last, a_first, a_first, host_id, a['ip']))
                    continue
                auto_rows.append((host_id, a['ip'], a.get('family'),
                                  a.get('scope'), a_first, a_last))
            if auto_rows:
                psycopg2.extras.execute_values(cursor, '''
                    INSERT INTO host_ips (host_id, ip_address, family, scope,
                                          first_seen_at, last_seen_at)
                    VALUES %s
                    ON CONFLICT (host_id, ip_address) DO UPDATE SET
                        family = EXCLUDED.family,
                        scope = EXCLUDED.scope,
                        first_seen_at = LEAST(host_ips.first_seen_at, EXCLUDED.first_seen_at),
                        last_seen_at = GREATEST(host_ips.last_seen_at, EXCLUDED.last_seen_at)
                ''', auto_rows)
        conn.commit()


def list_hosts():
    """All machines with their IP bindings (excluded ones flagged)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(_HOSTS_SELECT + '''
            GROUP BY h.id
            ORDER BY LOWER(COALESCE(h.name, h.discovered_name, h.host_key))
        ''')
        return [_host_row(r) for r in cursor.fetchall()]


def get_host(host_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(_HOSTS_SELECT + ' WHERE h.id = %s GROUP BY h.id', (host_id,))
        row = cursor.fetchone()
        return _host_row(row) if row else None


def create_manual_host(name, description=None, device_type=None):
    """A machine that exists only by user action (e.g. a server in another
    subnet whose MAC the capture never sees). Returns the new id."""
    import uuid
    if device_type and device_type not in DEVICE_TYPES:
        device_type = None
    key = 'manual:' + uuid.uuid4().hex[:12]
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO hosts (host_key, is_manual, name, name_edited,
                               description, device_type)
            VALUES (%s, TRUE, %s, TRUE, %s, %s) RETURNING id
        ''', (key, name, description, device_type))
        host_id = cursor.fetchone()['id']
        conn.commit()
        return host_id


def update_host(host_id, name=_UNSET, description=_UNSET, device_type=_UNSET,
                acknowledge_name_change=False):
    """Edit a machine. name='' resets it to the discovered name (and marks
    it as not edited, so it follows future per-IP labels again)."""
    sets, params = [], []
    if name is not _UNSET:
        name = (name or '').strip()
        if name:
            sets += ['name = %s', 'name_edited = TRUE']
            params.append(name)
        else:
            sets += ['name = discovered_name', 'name_edited = FALSE']
    if description is not _UNSET:
        sets.append('description = %s')
        params.append(description or None)
    if device_type is not _UNSET:
        if device_type and device_type not in DEVICE_TYPES:
            raise ValueError('invalid device_type')
        sets.append('device_type = %s')
        params.append(device_type or None)
    if acknowledge_name_change:
        sets += ['discovered_name_previous = NULL',
                 'discovered_name_changed_at = NULL']
    if not sets:
        return get_host(host_id)
    sets.append('updated_at = NOW()')
    params.append(host_id)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f'UPDATE hosts SET {", ".join(sets)} WHERE id = %s', params)
        found = cursor.rowcount > 0
        conn.commit()
    return get_host(host_id) if found else None


def delete_host(host_id):
    """Delete a MANUAL machine (its bindings go with it). Discovered hosts
    cannot be deleted — the next capture would recreate them; unbind their
    IPs instead. Returns True/False; raises ValueError for discovered hosts."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT is_manual FROM hosts WHERE id = %s', (host_id,))
        row = cursor.fetchone()
        if row is None:
            return False
        if not row['is_manual']:
            raise ValueError('only manual hosts can be deleted')
        cursor.execute('DELETE FROM hosts WHERE id = %s', (host_id,))
        conn.commit()
        return True


def bind_host_ip(host_id, ip, created_by=None):
    """Manually bind `ip` to a machine. The IP leaves any OTHER machine's
    manual bindings (an address belongs to one machine by user decision).
    Raises ValueError for addresses a host cannot own."""
    from pcap_analyzer.hosts import classify_ip
    try:
        ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        raise ValueError('invalid IP address')
    family, scope = classify_ip(ip)
    if family is None:
        raise ValueError('address cannot belong to a host (multicast/broadcast/unspecified)')
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM hosts WHERE id = %s', (host_id,))
        if cursor.fetchone() is None:
            return False
        cursor.execute('''
            DELETE FROM host_ips
            WHERE ip_address = %s AND source = 'manual' AND host_id <> %s
        ''', (ip, host_id))
        cursor.execute('''
            INSERT INTO host_ips (host_id, ip_address, family, scope, source,
                                  excluded, created_by)
            VALUES (%s, %s, %s, %s, 'manual', FALSE, %s)
            ON CONFLICT (host_id, ip_address) DO UPDATE SET
                source = 'manual', excluded = FALSE,
                created_by = EXCLUDED.created_by, created_at = NOW()
        ''', (host_id, ip, family, scope, created_by))
        conn.commit()
        return True


def unbind_host_ip(host_id, ip):
    """Remove an IP from a machine. A manual binding is deleted; an automatic
    one is marked excluded so later captures do not re-bind it.
    Returns 'deleted', 'excluded' or None (no such binding)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, source FROM host_ips WHERE host_id = %s AND ip_address = %s
        ''', (host_id, ip))
        row = cursor.fetchone()
        if row is None:
            return None
        if row['source'] == 'manual':
            cursor.execute('DELETE FROM host_ips WHERE id = %s', (row['id'],))
            outcome = 'deleted'
        else:
            cursor.execute('UPDATE host_ips SET excluded = TRUE WHERE id = %s', (row['id'],))
            outcome = 'excluded'
        conn.commit()
        return outcome


def get_host_binding_settings():
    """User decisions the analysis engine must honour
    (settings['host_bindings'] for HostIdentityAggregator)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT h.host_key, h.mac_address, hi.ip_address, hi.source, hi.excluded
            FROM host_ips hi JOIN hosts h ON h.id = hi.host_id
            WHERE hi.source = 'manual' OR hi.excluded
        ''')
        manual, excluded = [], []
        for r in cursor.fetchall():
            if r['excluded']:
                excluded.append({'host_key': r['host_key'], 'ip': r['ip_address']})
            else:
                manual.append({'host_key': r['host_key'], 'ip': r['ip_address'],
                               'mac': r['mac_address']})
        return {'manual': manual, 'excluded': excluded}


def get_ip_host_map():
    """{ip: machine} for every bound IP. A manual binding wins; otherwise the
    automatic binding seen most recently (DHCP may have moved the address)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT ON (hi.ip_address)
                   hi.ip_address, hi.source, h.id, h.host_key, h.mac_address,
                   h.is_manual, h.name, h.discovered_name,
                   h.discovered_name_previous, h.description, h.device_type
            FROM host_ips hi JOIN hosts h ON h.id = hi.host_id
            WHERE NOT hi.excluded
            ORDER BY hi.ip_address, (hi.source = 'manual') DESC,
                     hi.last_seen_at DESC NULLS LAST
        ''')
        out = {}
        for r in cursor.fetchall():
            d = dict(r)
            d['display_name'] = d.get('name') or d.get('discovered_name') or ''
            out[d.pop('ip_address')] = d
        return out


def get_device_types_by_ip():
    """IP -> device type for the detectors: per-IP labels, overridden by the
    machine's type when the IP is bound to a machine that has one."""
    types = {ip: (info.get('device_type') or DEVICE_TYPE_DEFAULT)
             for ip, info in get_all_ip_names().items()}
    try:
        for ip, h in get_ip_host_map().items():
            if h.get('device_type'):
                types[ip] = h['device_type']
    except Exception as e:
        print(f"[database] host device types unavailable: {e}")
    return types


# ==================== GEOLOCATION OPERATIONS ====================

def get_ip_geolocation(ip_address):
    """Get cached geolocation for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT country, country_code, city, region, lat, lon, isp, cached_at
            FROM ip_geolocation
            WHERE ip_address = %s
              AND cached_at > NOW() - INTERVAL '7 days'
        ''', (ip_address,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            if hasattr(result.get('cached_at'), 'isoformat'):
                result['cached_at'] = result['cached_at'].isoformat()
            return result
        return None


def get_all_ip_geolocations():
    """Get all cached geolocations"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, country, country_code, city, region, lat, lon, isp
            FROM ip_geolocation
            WHERE cached_at > NOW() - INTERVAL '7 days'
        ''')
        geos = {}
        for row in cursor.fetchall():
            geos[row['ip_address']] = {
                'country': row['country'],
                'country_code': row['country_code'],
                'city': row['city'],
                'region': row['region'],
                'lat': row['lat'],
                'lon': row['lon'],
                'isp': row['isp']
            }
        return geos


def save_ip_geolocation(ip_address, geo_data):
    """Save geolocation data for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ip_geolocation (ip_address, country, country_code, city, region, lat, lon, isp, cached_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT(ip_address) DO UPDATE SET
                country = EXCLUDED.country,
                country_code = EXCLUDED.country_code,
                city = EXCLUDED.city,
                region = EXCLUDED.region,
                lat = EXCLUDED.lat,
                lon = EXCLUDED.lon,
                isp = EXCLUDED.isp,
                cached_at = NOW()
        ''', (
            ip_address,
            geo_data.get('country'),
            geo_data.get('countryCode'),
            geo_data.get('city'),
            geo_data.get('regionName'),
            geo_data.get('lat'),
            geo_data.get('lon'),
            geo_data.get('isp')
        ))
        conn.commit()


# ==================== AGGREGATE STATISTICS ====================

def get_ip_in_range(ip_str, trusted_ranges):
    """
    Check if an IP belongs to a trusted range and return the range description
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for range_info in trusted_ranges:
            try:
                network = ipaddress.ip_network(range_info['cidr'], strict=False)
                if ip in network:
                    return range_info.get('description', range_info['cidr'])
            except ValueError:
                continue
    except ValueError:
        pass
    return None


def get_aggregated_results(scan_ids=None, trusted_ranges=None, date_from=None, date_to=None):
    """
    Get aggregated results from multiple scans
    If scan_ids is None, aggregates all scans (optionally filtered by date range)
    """
    trusted_ranges = trusted_ranges or []
    ip_names = get_all_ip_names()

    with get_connection() as conn:
        cursor = conn.cursor()

        # Build WHERE clause for scan filtering
        scan_conditions = []
        scan_params = []
        if scan_ids:
            scan_conditions.append('id = ANY(%s)')
            scan_params.append(scan_ids)
        if date_from:
            scan_conditions.append('analyzed_at >= %s')
            scan_params.append(date_from)
        if date_to:
            scan_conditions.append('analyzed_at <= %s')
            scan_params.append(date_to + ' 23:59:59')

        scan_where = ''
        if scan_conditions:
            scan_where = 'WHERE ' + ' AND '.join(scan_conditions)

        # Get matching scan IDs (for use in subqueries)
        cursor.execute(f'SELECT id FROM scans {scan_where}', scan_params)
        filtered_scan_ids = [row['id'] for row in cursor.fetchall()]

        if not filtered_scan_ids:
            return {
                'summary': {
                    'scan_count': 0,
                    'packet_count': 0,
                    'total_bytes': 0,
                    'duration': 0,
                    'first_scan': None,
                    'last_scan': None,
                    'analyzed_at': datetime.now().isoformat()
                },
                'ips': [],
                'protocols': [],
                'alerts': [],
                'protocol_ips': {},
                'ip_protocols': [],
                'traffic_timeline': []
            }

        # Use filtered IDs for all subsequent queries
        where_clause = 'WHERE scan_id = ANY(%s)'
        params = [filtered_scan_ids]

        # Get scan info
        cursor.execute(f'''
            SELECT COUNT(*) as scan_count,
                   SUM(packet_count) as total_packets,
                   SUM(total_bytes) as total_bytes,
                   SUM(duration) as total_duration,
                   MIN(start_time) as first_scan,
                   MAX(end_time) as last_scan
            FROM scans {scan_where}
        ''', scan_params)

        scan_summary = cursor.fetchone()

        # Aggregate IP stats
        cursor.execute(f'''
            SELECT
                ip_address,
                bool_or(is_local) as is_local,
                SUM(packets_sent) as packets_sent,
                SUM(packets_received) as packets_received,
                SUM(bytes_sent) as bytes_sent,
                SUM(bytes_received) as bytes_received,
                SUM(alert_count) as alert_count,
                COUNT(DISTINCT scan_id) as scan_count
            FROM ip_stats
            {where_clause}
            GROUP BY ip_address
            ORDER BY SUM(bytes_sent) + SUM(bytes_received) DESC
        ''', params)

        ips = []
        for row in cursor.fetchall():
            ip_addr = row['ip_address']

            # Get protocols from all scans for this IP
            cursor.execute('''
                SELECT protocols FROM ip_stats
                WHERE ip_address = %s AND scan_id = ANY(%s)
            ''', (ip_addr, filtered_scan_ids))

            protocols_set = set()
            for proto_row in cursor.fetchall():
                proto_list = json.loads(proto_row['protocols'] or '[]')
                protocols_set.update(proto_list)

            # Get name and group for this IP
            ip_info = ip_names.get(ip_addr, {})
            ip_name = ip_info.get('name', '')
            device_type = ip_info.get('device_type') or DEVICE_TYPE_DEFAULT
            group = get_ip_in_range(ip_addr, trusted_ranges)

            ips.append({
                'ip': ip_addr,
                'name': ip_name,
                'device_type': device_type,
                'group': group or '',
                'is_local': bool(row['is_local']),
                'packets_sent': row['packets_sent'],
                'packets_received': row['packets_received'],
                'bytes_sent': row['bytes_sent'],
                'bytes_received': row['bytes_received'],
                'protocols': list(protocols_set),
                'alert_count': row['alert_count'],
                'scan_count': row['scan_count']
            })

        # Aggregate protocol stats - first get total bytes
        cursor.execute(f'''
            SELECT SUM(bytes) as total_bytes
            FROM protocol_stats
            {where_clause}
        ''', params)
        total_bytes = cursor.fetchone()['total_bytes'] or 0

        cursor.execute(f'''
            SELECT
                name,
                SUM(packets) as packets,
                SUM(bytes) as bytes,
                MAX(risk_level) as risk_level,
                MAX(warning) as warning
            FROM protocol_stats
            {where_clause}
            GROUP BY name
            ORDER BY SUM(bytes) DESC
        ''', params)

        protocols = []
        for row in cursor.fetchall():
            percentage = (row['bytes'] / total_bytes * 100) if total_bytes > 0 else 0
            protocols.append({
                'name': row['name'],
                'packets': row['packets'],
                'bytes': row['bytes'],
                'percentage': round(percentage, 2),
                'risk_level': row['risk_level'],
                'warning': row['warning']
            })

        # Get all alerts
        cursor.execute(f'''
            SELECT
                a.severity, a.category, a.title, a.description,
                a.ip_address, a.details, a.recommendation, a.timestamp,
                s.filename
            FROM alerts a
            JOIN scans s ON a.scan_id = s.id
            WHERE a.scan_id = ANY(%s)
            ORDER BY
                CASE a.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                a.timestamp DESC
        ''', (filtered_scan_ids,))

        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'severity': row['severity'],
                'category': row['category'],
                'title': row['title'],
                'description': row['description'],
                'ip': row['ip_address'],
                'details': json.loads(row['details'] or '{}'),
                'recommendation': row['recommendation'],
                'timestamp': row['timestamp'],
                'filename': row['filename']
            })

        # Aggregate protocol-IP stats
        cursor.execute(f'''
            SELECT
                protocol_name,
                ip_address,
                SUM(packets) as packets,
                SUM(bytes) as bytes,
                bool_or(is_local) as is_local
            FROM protocol_ip_stats
            {where_clause}
            GROUP BY protocol_name, ip_address
            ORDER BY protocol_name, SUM(bytes) DESC
        ''', params)

        protocol_ips = {}
        ip_protocols_map = {}
        for row in cursor.fetchall():
            proto_name = row['protocol_name']
            ip_addr = row['ip_address']
            packets = row['packets']
            bytes_ = row['bytes']
            is_local_flag = bool(row['is_local'])

            if proto_name not in protocol_ips:
                protocol_ips[proto_name] = []
            protocol_ips[proto_name].append({
                'ip': ip_addr,
                'packets': packets,
                'bytes': bytes_,
                'is_local': is_local_flag
            })

            ip_entry = ip_protocols_map.get(ip_addr)
            if ip_entry is None:
                ip_entry = {
                    'ip': ip_addr,
                    'is_local': is_local_flag,
                    'total_packets': 0,
                    'total_bytes': 0,
                    'protocols': []
                }
                ip_protocols_map[ip_addr] = ip_entry
            ip_entry['total_packets'] += packets
            ip_entry['total_bytes'] += bytes_
            ip_entry['protocols'].append({
                'name': proto_name,
                'packets': packets,
                'bytes': bytes_,
                'peers': []
            })

        ip_protocols = []
        for entry in ip_protocols_map.values():
            entry['protocols'].sort(key=lambda p: p['bytes'], reverse=True)
            entry['protocol_count'] = len(entry['protocols'])
            ip_protocols.append(entry)
        ip_protocols.sort(key=lambda e: e['total_bytes'], reverse=True)

        return {
            'summary': {
                'scan_count': scan_summary['scan_count'],
                'packet_count': scan_summary['total_packets'] or 0,
                'total_bytes': scan_summary['total_bytes'] or 0,
                'duration': scan_summary['total_duration'] or 0,
                'first_scan': scan_summary['first_scan'],
                'last_scan': scan_summary['last_scan'],
                'analyzed_at': datetime.now().isoformat()
            },
            'ips': ips,
            'protocols': protocols,
            'alerts': alerts,
            'protocol_ips': protocol_ips,
            'ip_protocols': ip_protocols,
            'traffic_timeline': []
        }


def get_ip_evolution(ip_address, limit=10):
    """
    Get the evolution of an IP across multiple scans
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT
                s.id as scan_id,
                s.filename,
                s.analyzed_at,
                i.packets_sent,
                i.packets_received,
                i.bytes_sent,
                i.bytes_received,
                i.alert_count
            FROM ip_stats i
            JOIN scans s ON i.scan_id = s.id
            WHERE i.ip_address = %s
            ORDER BY s.analyzed_at DESC
            LIMIT %s
        ''', (ip_address, limit))

        evolution = []
        for row in cursor.fetchall():
            analyzed_at = row['analyzed_at']
            if hasattr(analyzed_at, 'isoformat'):
                analyzed_at = analyzed_at.isoformat()
            evolution.append({
                'scan_id': row['scan_id'],
                'filename': row['filename'],
                'analyzed_at': analyzed_at,
                'packets_sent': row['packets_sent'],
                'packets_received': row['packets_received'],
                'bytes_sent': row['bytes_sent'],
                'bytes_received': row['bytes_received'],
                'alert_count': row['alert_count']
            })

        return evolution


# ==================== BEHAVIORAL BASELINE OPERATIONS ====================

def get_known_external_ips(min_scans=1):
    """
    Return a set of every external IP ever recorded in ip_stats across all
    historical scans. Used to detect first-time external destinations.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, COUNT(DISTINCT scan_id) AS scan_count
            FROM ip_stats
            WHERE is_local = FALSE
            GROUP BY ip_address
            HAVING COUNT(DISTINCT scan_id) >= %s
        ''', (min_scans,))
        return {row['ip_address'] for row in cursor.fetchall()}


def get_host_protocols(ip_address):
    """Return set of protocols this host has ever used historically."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT protocol_name
            FROM protocol_ip_stats
            WHERE ip_address = %s
        ''', (ip_address,))
        return {row['protocol_name'] for row in cursor.fetchall()}


def get_host_volume_history(ip_address, limit=60):
    """
    Return list of (bytes_sent, bytes_received) for this IP across the most
    recent N scans. Ordered most-recent first.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT i.bytes_sent, i.bytes_received
            FROM ip_stats i
            JOIN scans s ON s.id = i.scan_id
            WHERE i.ip_address = %s
            ORDER BY s.analyzed_at DESC
            LIMIT %s
        ''', (ip_address, limit))
        return [(row['bytes_sent'], row['bytes_received']) for row in cursor.fetchall()]


def get_host_first_seen(ip_address):
    """Return the earliest analyzed_at timestamp this host appeared in (str|None)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT MIN(s.analyzed_at) AS first_seen
            FROM ip_stats i
            JOIN scans s ON s.id = i.scan_id
            WHERE i.ip_address = %s
        ''', (ip_address,))
        row = cursor.fetchone()
        if not row or not row['first_seen']:
            return None
        ts = row['first_seen']
        return ts.isoformat() if hasattr(ts, 'isoformat') else ts


def get_total_scan_count():
    """Total number of historical scans (used to gate baseline analysis)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) AS n FROM scans')
        row = cursor.fetchone()
        return int(row['n']) if row else 0


# Triage categories. Every alert lands in 'analisar' by default. The analyst
# moves it to 'falso_positivo' (which trains the FP classifier), 'resolvido',
# or 'sem_risco'. The auto-classifier also files alerts directly into
# 'sem_risco'. Only 'analisar' alerts count towards the alert badge.
VALID_TRIAGE_STATUSES = {'analisar', 'falso_positivo', 'resolvido', 'sem_risco'}
DEFAULT_TRIAGE_STATUS = 'analisar'


# ============================================================
#  Users / RBAC
# ============================================================

VALID_ROLES = ('viewer', 'analyst', 'admin')
ROLE_RANK = {'viewer': 0, 'analyst': 1, 'admin': 2}


def get_user_by_id(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, password_hash, role, enabled, created_at,
                   last_login_at, must_change_password
            FROM users WHERE id = %s
        ''', (user_id,))
        row = cursor.fetchone()
        return _serialize_user(row) if row else None


def get_user_by_username(username):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, password_hash, role, enabled, created_at,
                   last_login_at, must_change_password
            FROM users WHERE username = %s
        ''', (username,))
        row = cursor.fetchone()
        return _serialize_user(row) if row else None


def list_users():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, role, enabled, created_at, last_login_at,
                   must_change_password
            FROM users ORDER BY username
        ''')
        out = []
        for row in cursor.fetchall():
            d = dict(row)
            for ts in ('created_at', 'last_login_at'):
                if hasattr(d.get(ts), 'isoformat'):
                    d[ts] = d[ts].isoformat()
            out.append(d)
        return out


def count_users():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) AS n FROM users')
        return int(cursor.fetchone()['n'])


def create_user(username, password_hash, role='viewer', enabled=True,
                must_change_password=False):
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role; allowed: {VALID_ROLES}")
    if not username or not password_hash:
        raise ValueError("username and password_hash required")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, enabled, must_change_password)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
        ''', (username, password_hash, role, bool(enabled), bool(must_change_password)))
        uid = cursor.fetchone()['id']
        conn.commit()
        return uid


def update_user_password(user_id, password_hash, clear_must_change=True):
    with get_connection() as conn:
        cursor = conn.cursor()
        if clear_must_change:
            cursor.execute(
                'UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE id = %s',
                (password_hash, user_id),
            )
        else:
            cursor.execute(
                'UPDATE users SET password_hash = %s WHERE id = %s',
                (password_hash, user_id),
            )
        conn.commit()
        return cursor.rowcount > 0


def update_user_role(user_id, role):
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role; allowed: {VALID_ROLES}")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET role = %s WHERE id = %s', (role, user_id))
        conn.commit()
        return cursor.rowcount > 0


# ---- TOTP second factor ------------------------------------------------

def get_user_totp(user_id):
    """Return {'secret': str|None, 'enabled': bool} for the user, or None.

    Kept separate from get_user_by_id so the secret never rides along on the
    ambient user object that flows into templates / responses.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT totp_secret, totp_enabled FROM users WHERE id = %s',
            (user_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {'secret': row['totp_secret'], 'enabled': bool(row['totp_enabled'])}


def set_user_totp_secret(user_id, secret):
    """Store a pending (not-yet-confirmed) TOTP secret; leaves enabled FALSE."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET totp_secret = %s, totp_enabled = FALSE WHERE id = %s',
            (secret, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def enable_user_totp(user_id):
    """Flip totp_enabled TRUE once the user proved possession of the secret."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET totp_enabled = TRUE WHERE id = %s AND totp_secret IS NOT NULL',
            (user_id,),
        )
        conn.commit()
        return cursor.rowcount > 0


def clear_user_totp(user_id):
    """Remove the secret and disable TOTP (re-enrollment starts fresh)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET totp_secret = NULL, totp_enabled = FALSE WHERE id = %s',
            (user_id,),
        )
        conn.commit()
        return cursor.rowcount > 0


def update_user_enabled(user_id, enabled):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET enabled = %s WHERE id = %s',
            (bool(enabled), user_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def delete_user(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        ok = cursor.rowcount > 0
        conn.commit()
        return ok


def touch_user_login(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login_at = NOW() WHERE id = %s', (user_id,))
        conn.commit()


def _serialize_user(row):
    d = dict(row)
    for ts in ('created_at', 'last_login_at'):
        if hasattr(d.get(ts), 'isoformat'):
            d[ts] = d[ts].isoformat()
    return d


# ============================================================
#  Audit log
# ============================================================

# Genesis link for the first hashed row and any row whose predecessor predates
# the hash chain (legacy NULL row_hash).
_AUDIT_GENESIS = 'GENESIS'
# Arbitrary but fixed advisory-lock key so concurrent audit writes serialise
# on the chain tail instead of both reading the same prev_hash and forking it.
_AUDIT_LOCK_KEY = 738492


def _audit_occurred_iso(value):
    """Canonical UTC isoformat for an occurred_at value.

    The hash is computed over this exact string on write and recomputed from
    the DB value on verify, so both sides MUST normalise identically. TIMESTAMPTZ
    round-trips as a tz-aware datetime whose offset may differ from what we
    wrote (session tz), so we pin everything to UTC. Naive values (shouldn't
    happen for a TIMESTAMPTZ column) are assumed UTC.
    """
    if hasattr(value, 'astimezone'):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return value


def _audit_row_hash(prev_hash, occurred_at_iso, user_id, actor_ip, method,
                    path, action, target_type, target_id, status_code, extra_json):
    """Deterministic sha256 over the canonical serialisation of a row + the
    hash of the row before it. Recomputed byte-for-byte by verify_audit_chain,
    so field order / formatting here is part of the on-disk contract."""
    payload = json.dumps([
        prev_hash, occurred_at_iso, user_id, actor_ip, method, path, action,
        target_type, target_id, status_code, extra_json,
    ], ensure_ascii=False, separators=(',', ':'), sort_keys=False)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def write_audit(method, path, status_code, action=None, target_type=None,
                target_id=None, user_id=None, actor_ip=None, extra=None):
    """
    Insert an audit record, linked into the tamper-evident hash chain.

    Designed to be called from a Flask after_request hook, so it must not
    raise: any failure is logged and swallowed. A transaction-scoped advisory
    lock serialises concurrent writers so each row links the true chain tail.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # Serialise chain appends; the lock auto-releases at COMMIT.
            cursor.execute('SELECT pg_advisory_xact_lock(%s)', (_AUDIT_LOCK_KEY,))
            cursor.execute(
                'SELECT row_hash FROM audit_log '
                'WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1'
            )
            prev_row = cursor.fetchone()
            prev_hash = (prev_row['row_hash'] if prev_row else None) or _AUDIT_GENESIS

            occurred_dt = datetime.now(timezone.utc)
            occurred_at_iso = _audit_occurred_iso(occurred_dt)
            target_id_str = str(target_id) if target_id is not None else None
            extra_json = json.dumps(extra) if extra is not None else None
            row_hash = _audit_row_hash(
                prev_hash, occurred_at_iso, user_id, actor_ip, method, path,
                action, target_type, target_id_str, status_code, extra_json,
            )

            cursor.execute(
                '''
                INSERT INTO audit_log (
                    occurred_at, user_id, actor_ip, method, path, action,
                    target_type, target_id, status_code, extra,
                    prev_hash, row_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''',
                (
                    occurred_dt, user_id, actor_ip, method, path, action,
                    target_type, target_id_str, status_code, extra_json,
                    prev_hash, row_hash,
                ),
            )
            conn.commit()
    except Exception as e:
        print(f"[audit] write failed: {e}")


def verify_audit_chain(limit=None):
    """Recompute the hash chain over hashed audit rows and report tampering.

    Only rows with a non-null row_hash participate (rows written before the
    chain migration are legacy and unverifiable). Returns a dict:

        {ok: bool, checked: int, first_broken_id: int|None, reason: str|None}

    A broken link means a hashed row was deleted, edited, or reordered after
    the fact — exactly the trace an intruder would try to erase.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        q = ('SELECT id, occurred_at, user_id, actor_ip, method, path, action, '
             'target_type, target_id, status_code, extra, prev_hash, row_hash '
             'FROM audit_log WHERE row_hash IS NOT NULL ORDER BY id ASC')
        if limit:
            q += f' LIMIT {int(limit)}'
        cursor.execute(q)
        rows = cursor.fetchall()

    expected_prev = _AUDIT_GENESIS
    checked = 0
    for row in rows:
        d = dict(row)
        occurred_iso = _audit_occurred_iso(d.get('occurred_at'))
        if d.get('prev_hash') != expected_prev:
            return {'ok': False, 'checked': checked, 'first_broken_id': d['id'],
                    'reason': 'prev_hash does not match preceding row_hash '
                              '(row deleted, reordered, or inserted)'}
        recomputed = _audit_row_hash(
            d.get('prev_hash'), occurred_iso, d.get('user_id'), d.get('actor_ip'),
            d.get('method'), d.get('path'), d.get('action'), d.get('target_type'),
            d.get('target_id'), d.get('status_code'), d.get('extra'),
        )
        if recomputed != d.get('row_hash'):
            return {'ok': False, 'checked': checked, 'first_broken_id': d['id'],
                    'reason': 'row_hash mismatch (row contents were modified)'}
        expected_prev = d['row_hash']
        checked += 1

    return {'ok': True, 'checked': checked, 'first_broken_id': None, 'reason': None}


VALID_WEBHOOK_TYPES = {'slack', 'teams', 'generic', 'syslog', 'email'}


def list_webhooks(enabled_only=False):
    with get_connection() as conn:
        cursor = conn.cursor()
        q = '''
            SELECT id, name, type, target, min_severity, categories, extra,
                   enabled, created_at, last_used_at, last_error
            FROM webhooks
        '''
        if enabled_only:
            q += ' WHERE enabled = TRUE'
        q += ' ORDER BY id ASC'
        cursor.execute(q)
        out = []
        for row in cursor.fetchall():
            d = dict(row)
            for ts_field in ('created_at', 'last_used_at'):
                if hasattr(d.get(ts_field), 'isoformat'):
                    d[ts_field] = d[ts_field].isoformat()
            if d.get('extra'):
                try:
                    d['extra'] = json.loads(d['extra'])
                except (TypeError, ValueError):
                    pass
            out.append(d)
        return out


def create_webhook(name, type, target, min_severity='high', categories=None,
                   extra=None, enabled=True):
    if type not in VALID_WEBHOOK_TYPES:
        raise ValueError(f"invalid webhook type; allowed: {sorted(VALID_WEBHOOK_TYPES)}")
    if not name or not target:
        raise ValueError("name and target are required")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO webhooks
                (name, type, target, min_severity, categories, extra, enabled)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            name, type, target, min_severity,
            categories if isinstance(categories, str) else
                (','.join(categories) if categories else None),
            json.dumps(extra) if extra is not None else None,
            bool(enabled),
        ))
        rid = cursor.fetchone()['id']
        conn.commit()
        return rid


def delete_webhook(webhook_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM webhooks WHERE id = %s', (webhook_id,))
        ok = cursor.rowcount > 0
        conn.commit()
        return ok


def set_webhook_enabled(webhook_id, enabled):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE webhooks SET enabled = %s WHERE id = %s',
            (bool(enabled), webhook_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def mark_webhook_result(webhook_id, error=None):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE webhooks SET last_used_at = NOW(), last_error = %s WHERE id = %s',
            (error, webhook_id),
        )
        conn.commit()


def list_audit_log(limit=200, action=None, target_type=None, target_id=None,
                   user_id=None, since=None):
    """Read audit log with optional filters. Newest first."""
    conditions = []
    params = []
    if action:
        conditions.append('action = %s')
        params.append(action)
    if target_type:
        conditions.append('target_type = %s')
        params.append(target_type)
    if target_id is not None:
        conditions.append('target_id = %s')
        params.append(str(target_id))
    if user_id:
        conditions.append('user_id = %s')
        params.append(user_id)
    if since:
        conditions.append('occurred_at >= %s')
        params.append(since)
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    params.append(int(limit))
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f'''
            SELECT id, occurred_at, user_id, actor_ip, method, path, action,
                   target_type, target_id, status_code, extra
            FROM audit_log
            {where}
            ORDER BY occurred_at DESC
            LIMIT %s
            ''',
            params,
        )
        rows = []
        for row in cursor.fetchall():
            d = dict(row)
            if hasattr(d.get('occurred_at'), 'isoformat'):
                d['occurred_at'] = d['occurred_at'].isoformat()
            if d.get('extra'):
                try:
                    d['extra'] = json.loads(d['extra'])
                except (TypeError, ValueError):
                    pass
            rows.append(d)
        return rows


# ============================================================
#  Suppression rules
# ============================================================

# Scope guardrails: reject suppression rules broad enough to hide a whole
# swathe of traffic (the tool an intruder would reach for). A rule must pin at
# least one specific endpoint, and any CIDR must be no broader than these
# prefix lengths — /0-style "match the entire Internet" rules are refused.
_MIN_SUPPRESSION_PREFIX = {4: 8, 6: 16}

# Curated set of alert categories the detectors emit. Seeds the suppression-rule
# category picker on a fresh install (before any scan has run); the live
# get_alert_categories() unions this with the DISTINCT categories actually
# present so operator/custom categories also appear.
KNOWN_ALERT_CATEGORIES = (
    'anomaly', 'arp', 'beaconing', 'behavioral', 'brute_force', 'c2', 'dns',
    'exfil', 'exfiltration', 'exposure', 'first-seen', 'http', 'ics',
    'imported-zeek', 'incident', 'lateral', 'mac', 'malware-download', 'port',
    'protocol', 'scan', 'smb', 'threat-intel', 'tls', 'tunneling', 'user-rule',
    'yara-match',
)


def get_alert_categories():
    """Sorted union of curated known categories and those present in the
    alerts table — used to populate the suppression-rule category picker."""
    cats = set(KNOWN_ALERT_CATEGORIES)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT DISTINCT category FROM alerts "
                "WHERE category IS NOT NULL AND category <> ''"
            )
            for row in cursor.fetchall():
                cats.add(row['category'])
    except Exception as e:
        print(f"[database] alert category fetch failed: {e}")
    return sorted(cats)


def _validate_suppression_cidr(cidr):
    """Parse a CIDR and enforce the breadth floor. Returns the normalised net."""
    net = ipaddress.ip_network(cidr, strict=False)
    floor = _MIN_SUPPRESSION_PREFIX[net.version]
    if net.prefixlen < floor:
        raise ValueError(
            f"CIDR {cidr} is too broad to suppress on "
            f"(minimum /{floor} for IPv{net.version}); scope it to a smaller range")
    return net


def get_active_suppression_rules():
    """Return list of enabled rules. Cheap; called once per save_scan."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, title_pattern, category, src_ip, src_cidr,
                   dst_ip, dst_cidr, reason, hit_count
            FROM suppression_rules
            WHERE enabled = TRUE
        ''')
        return [dict(row) for row in cursor.fetchall()]


def list_suppression_rules():
    """Return all rules (enabled + disabled), newest first."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, title_pattern, category, src_ip, src_cidr,
                   dst_ip, dst_cidr, reason, created_by,
                   enabled, hit_count, created_at
            FROM suppression_rules
            ORDER BY created_at DESC
        ''')
        out = []
        for row in cursor.fetchall():
            d = dict(row)
            if hasattr(d.get('created_at'), 'isoformat'):
                d['created_at'] = d['created_at'].isoformat()
            out.append(d)
        return out


def create_suppression_rule(title_pattern=None, category=None, src_ip=None,
                            src_cidr=None, dst_ip=None, dst_cidr=None,
                            reason=None, enabled=True, created_by=None):
    """Insert a new rule.

    Guardrails (see _MIN_SUPPRESSION_PREFIX): a rule must constrain at least
    one specific endpoint — a category-only or title-only rule would silence
    that class network-wide, so it is refused. CIDRs are validated and breadth-
    capped up front so bad or over-broad input fails at create time.
    """
    has_endpoint = any([src_ip, src_cidr, dst_ip, dst_cidr])
    if not has_endpoint:
        raise ValueError(
            "a suppression rule must pin at least one endpoint "
            "(src_ip, src_cidr, dst_ip or dst_cidr); "
            "category/title alone would suppress that class network-wide")
    for scalar in (src_ip, dst_ip):
        if scalar:
            ipaddress.ip_address(scalar)  # raises ValueError on garbage
    for cidr in (src_cidr, dst_cidr):
        if cidr:
            _validate_suppression_cidr(cidr)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO suppression_rules
                (title_pattern, category, src_ip, src_cidr, dst_ip, dst_cidr,
                 reason, enabled, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
        ''', (title_pattern, category, src_ip, src_cidr, dst_ip, dst_cidr,
              reason, bool(enabled), created_by))
        row = cursor.fetchone()
        conn.commit()
        d = dict(row)
        if hasattr(d.get('created_at'), 'isoformat'):
            d['created_at'] = d['created_at'].isoformat()
        return d


def delete_suppression_rule(rule_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM suppression_rules WHERE id = %s', (rule_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted


def set_suppression_rule_enabled(rule_id, enabled):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE suppression_rules SET enabled = %s WHERE id = %s',
            (bool(enabled), rule_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def _alert_side_ips(alert, side):
    """Canonical endpoint IPs for one side of an alert.

    Prefers the top-level src_ips/dst_ips that alert_schema.normalize_alerts
    populates from every detector field variant. Falls back to legacy keys for
    alerts that never went through normalization (e.g. re-evaluated old blobs).
    """
    key = 'src_ips' if side == 'src' else 'dst_ips'
    ips = [ip for ip in (alert.get(key) or []) if isinstance(ip, str)]
    if ips:
        return ips
    details = alert.get('details') or {}
    if side == 'src':
        fallback = alert.get('ip') or details.get('src') or details.get('src_ip')
    else:
        fallback = details.get('dst') or details.get('dst_ip')
    return [fallback] if isinstance(fallback, str) and fallback else []


def _ip_matches(candidate_ips, exact, cidr):
    """True if any candidate IP satisfies the (exact, cidr) constraint pair.

    Both constraints are ANDed when present. An empty candidate list can never
    satisfy a set constraint — a rule that pins an endpoint the alert doesn't
    carry must NOT match (fail closed), so it can't silence unrelated alerts.
    """
    if exact:
        if not any(ip == exact for ip in candidate_ips):
            return False
    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        matched = False
        for ip in candidate_ips:
            try:
                if ipaddress.ip_address(ip) in net:
                    matched = True
                    break
            except ValueError:
                continue
        if not matched:
            return False
    return True


def _alert_matches_rule(alert, rule):
    """
    Match an alert against a suppression rule. Non-null rule fields must all
    match (AND); null rule fields are wildcards. Returns bool.
    """
    pat = rule.get('title_pattern')
    if pat and pat not in (alert.get('title') or ''):
        # Substring match (case-sensitive). Simple, predictable.
        return False
    cat = rule.get('category')
    if cat and cat != (alert.get('category') or ''):
        return False

    src_exact, src_cidr = rule.get('src_ip'), rule.get('src_cidr')
    if (src_exact or src_cidr) and not _ip_matches(
            _alert_side_ips(alert, 'src'), src_exact, src_cidr):
        return False

    dst_exact, dst_cidr = rule.get('dst_ip'), rule.get('dst_cidr')
    if (dst_exact or dst_cidr) and not _ip_matches(
            _alert_side_ips(alert, 'dst'), dst_exact, dst_cidr):
        return False

    return True


def evaluate_suppression(alert, rules):
    """Return matching rule id or None. Caller passes pre-fetched rule list."""
    for rule in rules:
        if _alert_matches_rule(alert, rule):
            return rule['id']
    return None


def increment_suppression_hits(rule_id_counts):
    """rule_id_counts: dict[rule_id -> n]. Bumps hit_count for each."""
    if not rule_id_counts:
        return
    with get_connection() as conn:
        cursor = conn.cursor()
        psycopg2.extras.execute_batch(
            cursor,
            'UPDATE suppression_rules SET hit_count = hit_count + %s WHERE id = %s',
            [(n, rid) for rid, n in rule_id_counts.items()],
        )
        conn.commit()


# ============================================================
#  Learned false-positive classifier
# ============================================================
#
# This is the "intelligence" behind the Sem Risco category. It is a
# memory-based (instance-based) classifier: every alert an analyst marks as
# 'falso_positivo' becomes a training example stored in fp_signatures. A new
# alert is classified as a false-positive ("sem_risco") when it matches a
# stored example on (category, title, exact source IP) — the same alert type
# from the same host the analyst already vetted. It is deliberately exact and
# explainable rather than a black-box model: the analyst can see exactly which
# signatures exist and why an alert was auto-classified.

def _alert_fp_key(alert):
    """Extract the (category, title, ip) signature key from an alert dict."""
    category = (alert.get('category') or '').strip()
    title = (alert.get('title') or '').strip()
    ip = alert.get('ip') or (alert.get('details') or {}).get('src')
    ip = (ip or '').strip() or None
    return category, title, ip


def _alert_matches_fp_signature(alert, sig):
    """True when an alert matches a learned FP signature (category+title+IP)."""
    category, title, ip = _alert_fp_key(alert)
    if not category or not title:
        return False
    if sig['category'] != category or sig['title'] != title:
        return False
    # Exact IP match. A signature with no IP only matches alerts with no IP.
    return (sig.get('ip_address') or None) == ip


def evaluate_fp_signatures(alert, signatures):
    """Return matching signature id or None. Caller passes pre-fetched list."""
    for sig in signatures:
        if _alert_matches_fp_signature(alert, sig):
            return sig['id']
    return None


def get_active_fp_signatures():
    """Return all learned false-positive signatures."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, category, title, ip_address, match_count,
                   created_at, last_matched_at
            FROM fp_signatures ORDER BY id
        ''')
        out = []
        for row in cursor.fetchall():
            d = dict(row)
            for ts in ('created_at', 'last_matched_at'):
                if hasattr(d.get(ts), 'isoformat'):
                    d[ts] = d[ts].isoformat()
            out.append(d)
        return out


def learn_fp_signature(category, title, ip_address):
    """
    Record (or refresh) a false-positive signature. Called whenever an analyst
    marks an alert as 'falso_positivo'. Idempotent: re-marking the same alert
    type just touches the existing row instead of creating a duplicate.
    """
    category = (category or '').strip()
    title = (title or '').strip()
    ip_address = (ip_address or '').strip() or None
    if not category or not title:
        return None
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO fp_signatures (category, title, ip_address)
            VALUES (%s, %s, %s)
            ON CONFLICT (category, title, COALESCE(ip_address, ''))
            DO UPDATE SET last_matched_at = NOW()
            RETURNING id
        ''', (category, title, ip_address))
        row = cursor.fetchone()
        conn.commit()
        return row['id'] if row else None


def increment_fp_signature_hits(sig_id_counts):
    """sig_id_counts: dict[signature_id -> n]. Bumps match_count for each."""
    if not sig_id_counts:
        return
    with get_connection() as conn:
        cursor = conn.cursor()
        psycopg2.extras.execute_batch(
            cursor,
            'UPDATE fp_signatures SET match_count = match_count + %s, '
            'last_matched_at = NOW() WHERE id = %s',
            [(n, sid) for sid, n in sig_id_counts.items()],
        )
        conn.commit()


def delete_fp_signature(sig_id):
    """Forget a learned false-positive signature."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM fp_signatures WHERE id = %s', (sig_id,))
        ok = cursor.rowcount > 0
        conn.commit()
        return ok


def get_alert_status_counts(scan_id):
    """Return {triage_status: count} for a scan — drives the category filters."""
    counts = {s: 0 for s in VALID_TRIAGE_STATUSES}
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT triage_status, COUNT(*) AS n
            FROM alerts WHERE scan_id = %s GROUP BY triage_status
        ''', (scan_id,))
        for row in cursor.fetchall():
            counts[row['triage_status']] = int(row['n'])
    return counts


def get_alerts_by_scan(scan_id, status=None, order='severity'):
    """
    Return full alert rows for a scan including triage state. Alerts in the
    JSON blob are point-in-time snapshots and don't carry DB ids; this
    endpoint is the source of truth for triage UIs.

    order='severity' (default) sorts by severity then id; order='id' returns
    rows in insertion order, which matches the order of results_json['alerts']
    — used to positionally merge DB triage state back into the JSON blob.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        query = '''
            SELECT id, scan_id, severity, category, title, description,
                   ip_address, details, recommendation, timestamp,
                   triage_status, triage_note, triage_assignee, triaged_at
            FROM alerts
            WHERE scan_id = %s
        '''
        params = [scan_id]
        if status:
            query += ' AND triage_status = %s'
            params.append(status)
        if order == 'id':
            query += ' ORDER BY id ASC'
        else:
            query += ' ORDER BY CASE severity'
            query += "  WHEN 'critical' THEN 1 WHEN 'high' THEN 2"
            query += "  WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, id ASC"
        cursor.execute(query, params)
        out = []
        for row in cursor.fetchall():
            d = dict(row)
            if hasattr(d.get('triaged_at'), 'isoformat'):
                d['triaged_at'] = d['triaged_at'].isoformat()
            d['details'] = json.loads(d.get('details') or '{}')
            d['ip'] = d.pop('ip_address', None)
            out.append(d)
        return out


def update_alert_triage(alert_id, status=None, note=None, assignee=None):
    """
    Update triage fields on an alert. Only fields the caller passes are
    touched. Returns the updated row, or None if not found.
    """
    if status and status not in VALID_TRIAGE_STATUSES:
        raise ValueError(f"invalid status: {status}")
    sets = []
    params = []
    if status is not None:
        sets.append('triage_status = %s')
        params.append(status)
    if note is not None:
        sets.append('triage_note = %s')
        params.append(note[:2000] if isinstance(note, str) else note)
    if assignee is not None:
        sets.append('triage_assignee = %s')
        params.append(assignee[:200] if isinstance(assignee, str) else assignee)
    if not sets:
        return None
    sets.append('triaged_at = NOW()')
    params.append(alert_id)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f'UPDATE alerts SET {", ".join(sets)} WHERE id = %s '
            f'RETURNING id, triage_status, triage_note, triage_assignee, '
            f'triaged_at, category, title, ip_address',
            params,
        )
        row = cursor.fetchone()
        conn.commit()
        if not row:
            return None
        d = dict(row)
        if hasattr(d.get('triaged_at'), 'isoformat'):
            d['triaged_at'] = d['triaged_at'].isoformat()

    # Marking an alert as a false positive trains the classifier: the next
    # scan that produces the same alert type from the same host auto-files it
    # as 'sem_risco'. Done outside the transaction above — a learning failure
    # must not roll back the triage update the analyst explicitly requested.
    if status == 'falso_positivo':
        try:
            learn_fp_signature(d.get('category'), d.get('title'), d.get('ip_address'))
        except Exception as e:
            print(f"[database] fp signature learning failed: {e}")

    # Don't leak the extra columns we only fetched for the learning step.
    for k in ('category', 'title', 'ip_address'):
        d.pop(k, None)
    return d


def update_alerts_triage_bulk(alert_ids, status=None, note=None, assignee=None):
    """Apply the same triage update to many alerts in a single statement.

    The single-alert path issued one UPDATE + one DB connection per alert;
    triaging a filtered batch that way meant N round-trips and N audit rows.
    Here one `UPDATE ... WHERE id = ANY(...)` covers the whole set. Marking
    'falso_positivo' still trains the FP classifier, but only once per distinct
    (category, title, ip) so a batch doesn't issue redundant learning writes.

    Returns the list of updated rows (same shape as update_alert_triage).
    """
    if status and status not in VALID_TRIAGE_STATUSES:
        raise ValueError(f"invalid status: {status}")

    ids = []
    for a in (alert_ids or []):
        try:
            ids.append(int(a))
        except (TypeError, ValueError):
            continue
    ids = list(dict.fromkeys(ids))  # dedupe, keep order
    if not ids:
        return []

    sets = []
    params = []
    if status is not None:
        sets.append('triage_status = %s')
        params.append(status)
    if note is not None:
        sets.append('triage_note = %s')
        params.append(note[:2000] if isinstance(note, str) else note)
    if assignee is not None:
        sets.append('triage_assignee = %s')
        params.append(assignee[:200] if isinstance(assignee, str) else assignee)
    if not sets:
        return []
    sets.append('triaged_at = NOW()')
    params.append(ids)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f'UPDATE alerts SET {", ".join(sets)} WHERE id = ANY(%s) '
            f'RETURNING id, triage_status, triage_note, triage_assignee, '
            f'triaged_at, category, title, ip_address',
            params,
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.commit()

    for d in rows:
        if hasattr(d.get('triaged_at'), 'isoformat'):
            d['triaged_at'] = d['triaged_at'].isoformat()

    # Train the FP classifier once per distinct signature (see update_alert_triage).
    if status == 'falso_positivo':
        seen = set()
        for d in rows:
            key = ((d.get('category') or '').strip(),
                   (d.get('title') or '').strip(),
                   (d.get('ip_address') or '').strip())
            if key in seen:
                continue
            seen.add(key)
            try:
                learn_fp_signature(d.get('category'), d.get('title'), d.get('ip_address'))
            except Exception as e:
                print(f"[database] fp signature learning failed: {e}")

    # Drop the columns fetched only for the learning step.
    for d in rows:
        for k in ('category', 'title', 'ip_address'):
            d.pop(k, None)
    return rows


def record_assets(scan_id, scan_time_iso, assets):
    """
    Upsert per-MAC asset records. assets is the dict returned by
    asset_inventory.extract_assets. Updates ttl/os/dhcp fields with latest
    non-null values; preserves first_seen_at; bumps scan_count.
    """
    if not assets:
        return
    rows = []
    for mac, a in assets.items():
        rows.append((
            mac,
            json.dumps(a.get("ip_addresses") or []),
            a.get("os_guess"),
            a.get("ttl_initial"),
            a.get("ttl_observed"),
            a.get("dhcp_vendor"),
            a.get("dhcp_hostname"),
            a.get("dhcp_param_list_hash"),
            scan_time_iso,
            scan_time_iso,
            scan_id,
        ))
    with get_connection() as conn:
        cursor = conn.cursor()
        psycopg2.extras.execute_batch(
            cursor,
            '''
            INSERT INTO assets (
                mac_address, ip_addresses, os_guess, ttl_initial, ttl_observed,
                dhcp_vendor, dhcp_hostname, dhcp_param_list_hash,
                first_seen_at, last_seen_at, last_scan_id
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (mac_address) DO UPDATE SET
                ip_addresses = EXCLUDED.ip_addresses,
                os_guess = COALESCE(EXCLUDED.os_guess, assets.os_guess),
                ttl_initial = COALESCE(EXCLUDED.ttl_initial, assets.ttl_initial),
                ttl_observed = COALESCE(EXCLUDED.ttl_observed, assets.ttl_observed),
                dhcp_vendor = COALESCE(EXCLUDED.dhcp_vendor, assets.dhcp_vendor),
                dhcp_hostname = COALESCE(EXCLUDED.dhcp_hostname, assets.dhcp_hostname),
                dhcp_param_list_hash = COALESCE(EXCLUDED.dhcp_param_list_hash, assets.dhcp_param_list_hash),
                last_seen_at = GREATEST(assets.last_seen_at, EXCLUDED.last_seen_at),
                scan_count = assets.scan_count + 1,
                last_scan_id = EXCLUDED.last_scan_id
            ''',
            rows,
        )
        conn.commit()


def get_all_assets():
    """Return list of asset records (sorted by last_seen_at desc)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT mac_address, ip_addresses, os_guess, ttl_initial, ttl_observed,
                   dhcp_vendor, dhcp_hostname, dhcp_param_list_hash,
                   first_seen_at, last_seen_at, scan_count
            FROM assets
            ORDER BY last_seen_at DESC
        ''')
        out = []
        for row in cursor.fetchall():
            d = dict(row)
            for ts_field in ('first_seen_at', 'last_seen_at'):
                if hasattr(d.get(ts_field), 'isoformat'):
                    d[ts_field] = d[ts_field].isoformat()
            d['ip_addresses'] = json.loads(d.get('ip_addresses') or '[]')
            out.append(d)
        return out


def get_known_artifact_keys(types=None):
    """
    Return the set of (artifact_type, artifact_value) pairs already recorded.
    Used by correlation.detect_new_artifacts to skip artifacts we've seen
    before. `types` is an optional iterable to filter.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        if types:
            cursor.execute('''
                SELECT artifact_type, artifact_value
                FROM artifact_seen
                WHERE artifact_type = ANY(%s)
            ''', (list(types),))
        else:
            cursor.execute('SELECT artifact_type, artifact_value FROM artifact_seen')
        return {(row['artifact_type'], row['artifact_value']) for row in cursor.fetchall()}


def record_artifacts(scan_id, scan_time_iso, observed):
    """
    Upsert every observed artifact for this scan. `observed` is the dict
    produced by PCAPAnalyzer._collect_observed_artifacts: {type: [values]}.
    Updates last_seen_at / scan_count; preserves first_seen_at.
    """
    if not observed:
        return
    rows = []
    for artifact_type, values in observed.items():
        for v in values:
            if not v:
                continue
            rows.append((artifact_type, v))
    if not rows:
        return

    with get_connection() as conn:
        cursor = conn.cursor()
        psycopg2.extras.execute_batch(
            cursor,
            '''
            INSERT INTO artifact_seen (
                artifact_type, artifact_value,
                first_seen_at, last_seen_at, scan_count, last_scan_id
            )
            VALUES (%s, %s, %s, %s, 1, %s)
            ON CONFLICT (artifact_type, artifact_value) DO UPDATE SET
                last_seen_at = GREATEST(artifact_seen.last_seen_at, EXCLUDED.last_seen_at),
                scan_count = artifact_seen.scan_count + 1,
                last_scan_id = EXCLUDED.last_scan_id
            ''',
            [(t, v, scan_time_iso, scan_time_iso, scan_id) for (t, v) in rows],
        )
        conn.commit()


def get_active_hours_for_ips(ip_list):
    """
    For each IP in `ip_list`, return the set of hour-of-week buckets
    (0..167, Monday=0) where the host had any traffic in past scans.

    Returns dict: ip -> set(int).
    """
    if not ip_list:
        return {}
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT i.ip_address, s.start_time
            FROM ip_stats i
            JOIN scans s ON s.id = i.scan_id
            WHERE i.ip_address = ANY(%s)
              AND s.start_time IS NOT NULL
        ''', (list(ip_list),))
        out = {}
        for row in cursor.fetchall():
            ts = row['start_time']
            try:
                if hasattr(ts, 'isoformat'):
                    dt = ts
                else:
                    dt = datetime.fromisoformat(ts)
                hour_of_week = dt.weekday() * 24 + dt.hour
            except (ValueError, TypeError):
                continue
            out.setdefault(row['ip_address'], set()).add(hour_of_week)
        return out


# ==================== THREAT INTELLIGENCE OPERATIONS ====================

def get_ip_reputation(ip_address):
    """Get cached reputation for an IP (7-day TTL)"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT reputation_score, is_malicious, abuse_confidence,
                   sources, last_seen, cached_at
            FROM ip_reputation
            WHERE ip_address = %s
              AND cached_at > NOW() - INTERVAL '7 days'
        ''', (ip_address,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            if hasattr(result.get('cached_at'), 'isoformat'):
                result['cached_at'] = result['cached_at'].isoformat()
            result['sources'] = json.loads(result.get('sources') or '[]')
            return result
        return None


def save_ip_reputation(ip_address, reputation_data):
    """Save reputation data for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ip_reputation (
                ip_address, reputation_score, is_malicious,
                abuse_confidence, sources, last_seen, cached_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT(ip_address) DO UPDATE SET
                reputation_score = EXCLUDED.reputation_score,
                is_malicious = EXCLUDED.is_malicious,
                abuse_confidence = EXCLUDED.abuse_confidence,
                sources = EXCLUDED.sources,
                last_seen = EXCLUDED.last_seen,
                cached_at = NOW()
        ''', (
            ip_address,
            reputation_data.get('reputation_score', 0),
            reputation_data.get('is_malicious', False),
            reputation_data.get('abuse_confidence', 0),
            json.dumps(reputation_data.get('sources', [])),
            reputation_data.get('last_seen')
        ))
        conn.commit()


def get_all_ip_reputations():
    """Get all cached reputations (within 7-day TTL)"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, reputation_score, is_malicious,
                   abuse_confidence, sources, last_seen
            FROM ip_reputation
            WHERE cached_at > NOW() - INTERVAL '7 days'
        ''')
        reps = {}
        for row in cursor.fetchall():
            reps[row['ip_address']] = {
                'reputation_score': row['reputation_score'],
                'is_malicious': row['is_malicious'],
                'abuse_confidence': row['abuse_confidence'],
                'sources': json.loads(row['sources'] or '[]'),
                'last_seen': row['last_seen']
            }
        return reps


# ============================================================
#  Carved files (HTTP file carving + hash reputation)
# ============================================================

def save_carved_files(scan_id, files):
    """Persist a batch of carved file metadata for *scan_id*.

    *files* is a list of dicts as returned by file_carving.carve_http_files.
    Reputation columns (vt_data, mb_data, malicious, labels, looked_up_at)
    are written later by update_carved_file_reputation once the slow-queue
    enrichment runs.

    Idempotent within a scan via UNIQUE(scan_id, sha256) — a second insert
    of the same hash is a no-op.
    """
    if not files:
        return 0
    inserted = 0
    with get_connection() as conn:
        cursor = conn.cursor()
        for f in files:
            try:
                cursor.execute('''
                    INSERT INTO carved_files (
                        scan_id, sha256, sha1, md5, filename, content_type,
                        size_bytes, source_url, src_ip, dst_ip, protocol,
                        direction, family, on_disk_path
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id, sha256) DO NOTHING
                ''', (
                    scan_id,
                    f.get('sha256'),
                    f.get('sha1'),
                    f.get('md5'),
                    f.get('filename'),
                    f.get('content_type'),
                    f.get('size_bytes'),
                    f.get('source_url'),
                    f.get('src_ip'),
                    f.get('dst_ip'),
                    f.get('protocol', 'http'),
                    f.get('direction'),
                    f.get('family'),
                    f.get('on_disk_path'),
                ))
                inserted += cursor.rowcount
            except Exception as e:
                print(f"[db] save_carved_files error for {f.get('sha256','?')[:12]}: {e}")
        conn.commit()
    return inserted


def get_carved_files_for_scan(scan_id):
    """Return the list of carved files for *scan_id*, newest first."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, scan_id, sha256, sha1, md5, filename, content_type,
                   size_bytes, source_url, src_ip, dst_ip, protocol,
                   direction, family, on_disk_path, malicious, labels,
                   vt_data, mb_data, looked_up_at,
                   yara_matches, yara_severity, yara_scanned_at,
                   carved_at
            FROM carved_files
            WHERE scan_id = %s
            ORDER BY malicious DESC, carved_at DESC
        ''', (scan_id,))
        out = []
        for row in cursor.fetchall():
            out.append({
                'id': row['id'],
                'scan_id': row['scan_id'],
                'sha256': row['sha256'],
                'sha1': row['sha1'],
                'md5': row['md5'],
                'filename': row['filename'],
                'content_type': row['content_type'],
                'size_bytes': row['size_bytes'],
                'source_url': row['source_url'],
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'protocol': row['protocol'],
                'direction': row['direction'],
                'family': row['family'],
                'on_disk_path': row['on_disk_path'],
                'malicious': bool(row['malicious']),
                'labels': json.loads(row['labels'] or '[]'),
                'vt_data': row['vt_data'],
                'mb_data': row['mb_data'],
                'looked_up_at': (row['looked_up_at'].isoformat()
                                 if row['looked_up_at'] else None),
                'yara_matches': row['yara_matches'],
                'yara_severity': row['yara_severity'],
                'yara_scanned_at': (row['yara_scanned_at'].isoformat()
                                    if row['yara_scanned_at'] else None),
                'carved_at': (row['carved_at'].isoformat()
                              if row['carved_at'] else None),
            })
        return out


def get_carved_file_by_sha256(sha256):
    """Look up a carved file globally (across scans) by SHA-256.

    Used by the admin download endpoint and to avoid re-querying VT/MB on a
    hash we've already enriched.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT scan_id, sha256, filename, content_type, size_bytes,
                   on_disk_path, malicious, labels, vt_data, mb_data,
                   looked_up_at
            FROM carved_files
            WHERE sha256 = %s
            ORDER BY carved_at DESC
            LIMIT 1
        ''', (sha256,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            'scan_id': row['scan_id'],
            'sha256': row['sha256'],
            'filename': row['filename'],
            'content_type': row['content_type'],
            'size_bytes': row['size_bytes'],
            'on_disk_path': row['on_disk_path'],
            'malicious': bool(row['malicious']),
            'labels': json.loads(row['labels'] or '[]'),
            'vt_data': row['vt_data'],
            'mb_data': row['mb_data'],
            'looked_up_at': (row['looked_up_at'].isoformat()
                             if row['looked_up_at'] else None),
        }


def append_alerts_to_scan(scan_id, alerts):
    """Insert *alerts* into the alerts table associated with *scan_id*.

    Used by background enrichment (slow-queue Celery task) to post-attach
    alerts derived from network-bound work — hash lookups, threat-intel
    matches, etc. — that wasn't available at original save time. Bumps
    scans.alert_count by the number of alerts in 'analisar' state so the UI
    badge reflects the new findings.
    """
    if not alerts:
        return 0
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT analyzed_at FROM scans WHERE id = %s', (scan_id,),
        )
        row = cursor.fetchone()
        if not row:
            return 0
        analyzed_at = row['analyzed_at']
        try:
            alert_date = (analyzed_at.date()
                          if hasattr(analyzed_at, 'date')
                          else datetime.fromisoformat(str(analyzed_at)[:10]).date())
        except (ValueError, TypeError):
            alert_date = datetime.now().date()
        _ensure_month_partition(cursor, alert_date)

        analisar_added = 0
        for alert in alerts:
            cursor.execute('''
                INSERT INTO alerts (
                    scan_id, alert_date, severity, category, title, description,
                    ip_address, details, recommendation, timestamp,
                    triage_status, suppressed_by_rule
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                scan_id,
                alert_date,
                alert.get('severity'),
                alert.get('category'),
                alert.get('title'),
                alert.get('description'),
                alert.get('ip'),
                json.dumps(alert.get('details', {})),
                alert.get('recommendation'),
                alert.get('timestamp') or datetime.now().isoformat(),
                'analisar',
                None,
            ))
            alert['id'] = cursor.fetchone()['id']
            analisar_added += 1

        if analisar_added:
            cursor.execute(
                'UPDATE scans SET alert_count = alert_count + %s WHERE id = %s',
                (analisar_added, scan_id),
            )
        conn.commit()
    return analisar_added


def update_scan_results(scan_id, results):
    """Overwrite scans.results_json for an existing scan with an enriched blob.

    Background enrichment (geolocation, IP/domain reputation, carved-file and
    YARA alerts) mutates the in-memory results after the initial save_scan().
    Persisting the blob here lets the scan view reflect that enrichment on
    reload. Only results_json is rewritten; the denormalized counts and the
    alerts table are maintained by save_scan / append_alerts_to_scan.

    Returns the number of rows updated (0 if scan_id is unknown).
    """
    if not scan_id or results is None:
        return 0
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE scans SET results_json = %s WHERE id = %s',
            (json.dumps(results), scan_id),
        )
        updated = cursor.rowcount
        conn.commit()
    return updated


def update_carved_file_yara_matches(sha256, payload):
    """Persist YARA scan results for a carved file.

    *payload* is the shape returned by yara_scan.scan_files()[sha256]:
        {'matches': [...], 'severity': 'high'}

    If the worst match severity is 'critical' or 'high' we also flip the
    `malicious` flag (so the existing carved-files UI badge surfaces it) and
    merge the rule names into the `labels` JSON array (de-duped).
    Returns the number of rows updated.
    """
    if not sha256 or not payload:
        return 0
    matches = payload.get('matches') or []
    severity = payload.get('severity') or 'medium'
    promote_malicious = severity in ('critical', 'high')
    rule_names = [m.get('rule') for m in matches if m.get('rule')]

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, labels, malicious FROM carved_files WHERE sha256 = %s',
            (sha256,),
        )
        rows = cursor.fetchall()
        if not rows:
            return 0

        updated = 0
        for row in rows:
            existing_labels = []
            try:
                existing_labels = json.loads(row['labels'] or '[]')
            except (TypeError, ValueError):
                existing_labels = []
            merged = list(existing_labels)
            for name in rule_names:
                tag = f'yara:{name}'
                if tag not in merged:
                    merged.append(tag)

            new_malicious = bool(row['malicious']) or promote_malicious

            cursor.execute('''
                UPDATE carved_files
                SET yara_matches = %s,
                    yara_severity = %s,
                    yara_scanned_at = NOW(),
                    labels = %s,
                    malicious = %s
                WHERE id = %s
            ''', (
                json.dumps(matches),
                severity,
                json.dumps(merged),
                new_malicious,
                row['id'],
            ))
            updated += cursor.rowcount
        conn.commit()
    return updated


def update_carved_file_reputation(sha256, verdict):
    """Update VT/MB reputation columns for every carved_files row matching
    *sha256* (across scans). *verdict* shape comes from hash_lookup.lookup_file_hash.
    """
    if not sha256 or verdict is None:
        return 0
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE carved_files
            SET malicious = %s,
                labels = %s,
                vt_data = %s,
                mb_data = %s,
                looked_up_at = NOW()
            WHERE sha256 = %s
        ''', (
            bool(verdict.get('malicious')),
            json.dumps(verdict.get('labels') or []),
            json.dumps(verdict.get('virustotal')) if verdict.get('virustotal') is not None else None,
            json.dumps(verdict.get('malwarebazaar')) if verdict.get('malwarebazaar') is not None else None,
            sha256,
        ))
        updated = cursor.rowcount
        conn.commit()
    return updated


# ============================================================
#  Retention & partition management
# ============================================================

def purge_old_scans(retention_days):
    """Delete scans (and their cascade-linked alerts) older than *retention_days*.

    Returns the number of scans deleted.
    """
    cutoff = datetime.now() - timedelta(days=int(retention_days))
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM scans WHERE analyzed_at < %s RETURNING id',
            (cutoff,),
        )
        deleted = cursor.rowcount
        conn.commit()
    return deleted


def get_referenced_pcap_filenames():
    """Return the set of PCAP filenames still referenced by a scan row.

    This is the source of truth for "still in use": a server-side copy under
    UPLOAD_FOLDER whose basename isn't in this set is an orphan.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT DISTINCT filename FROM scans WHERE filename IS NOT NULL'
        )
        return {row['filename'] for row in cursor.fetchall()}


def cleanup_orphaned_pcaps(upload_folder, artifacts_root=None,
                           min_age_seconds=86400, dry_run=False):
    """Delete server-side PCAP copies (and their carved artifacts) that no scan
    row references any more.

    SAFETY — this only ever touches files the app itself wrote under
    ``upload_folder`` / ``artifacts_root``. The file the user analysed lives on
    *their* machine: on upload Flask streams the HTTP body into a fresh copy in
    ``upload_folder``, so the original is never reachable from here. Symlinks
    are skipped outright (a link could point outside the app), and only entries
    whose basename is NOT referenced by any scan are removed.

    ``min_age_seconds`` guards the upload→analyze race: a freshly uploaded file
    has no scan row until analysis finishes, so it would otherwise look like an
    orphan. Files modified within this window are left alone (default 24h, far
    longer than any analysis; the periodic purge runs daily so the file is
    reaped on a later pass once its scan either landed or never will).

    Returns a dict: ``{removed_pcaps, removed_artifact_dirs, freed_bytes,
    errors}``. Per-entry failures are collected, never raised — a single
    undeletable file must not abort the sweep.
    """
    result = {'removed_pcaps': [], 'removed_artifact_dirs': [],
              'freed_bytes': 0, 'errors': []}
    if not upload_folder or not os.path.isdir(upload_folder):
        return result

    referenced = get_referenced_pcap_filenames()
    # Carving derives the artifacts dir name from the basename WITHOUT extension
    # (see pcap_analyzer/_core.py), so mirror that to decide which dirs survive.
    referenced_keys = {os.path.splitext(f)[0] for f in referenced}

    now = time.time()
    upload_root = os.path.realpath(upload_folder)

    def _too_new(path):
        try:
            return (now - os.path.getmtime(path)) < min_age_seconds
        except OSError:
            return True  # can't stat -> err on the side of keeping it

    try:
        entries = os.listdir(upload_root)
    except OSError as e:
        result['errors'].append(f'listdir {upload_root}: {e}')
        return result

    for name in entries:
        fpath = os.path.join(upload_root, name)
        # Leave symlinks and anything that isn't a plain file untouched.
        if os.path.islink(fpath) or not os.path.isfile(fpath):
            continue
        if name in referenced or _too_new(fpath):
            continue
        try:
            size = os.path.getsize(fpath)
        except OSError:
            size = 0
        if not dry_run:
            try:
                os.remove(fpath)
            except OSError as e:
                result['errors'].append(f'remove {name}: {e}')
                continue
        result['removed_pcaps'].append(name)
        result['freed_bytes'] += size

    if artifacts_root is None:
        artifacts_root = os.path.normpath(
            os.path.join(upload_root, '..', 'artifacts')
        )
    if os.path.isdir(artifacts_root):
        art_root = os.path.realpath(artifacts_root)
        try:
            art_entries = os.listdir(art_root)
        except OSError as e:
            result['errors'].append(f'listdir {art_root}: {e}')
            art_entries = []
        for key in art_entries:
            dpath = os.path.join(art_root, key)
            if os.path.islink(dpath) or not os.path.isdir(dpath):
                continue
            if key in referenced_keys or _too_new(dpath):
                continue
            if not dry_run:
                try:
                    shutil.rmtree(dpath)
                except OSError as e:
                    result['errors'].append(f'rmtree {key}: {e}')
                    continue
            result['removed_artifact_dirs'].append(key)

    return result


def list_alert_partitions():
    """Return sorted list of monthly alert partition names (excludes default)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.relname
            FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            WHERE p.relname = 'alerts'
              AND c.relname != 'alerts_default'
            ORDER BY c.relname
        """)
        return [row['relname'] for row in cursor.fetchall()]


def drop_old_partitions(retention_days):
    """Drop monthly alert partitions whose entire date range is beyond *retention_days*.

    Returns list of dropped partition names.
    """
    cutoff = (datetime.now() - timedelta(days=int(retention_days))).date()
    partitions = list_alert_partitions()
    dropped = []
    with get_connection() as conn:
        cursor = conn.cursor()
        for pname in partitions:
            # alerts_YYYY_MM
            parts = pname.split('_')
            if len(parts) < 3:
                continue
            try:
                year, month = int(parts[-2]), int(parts[-1])
            except ValueError:
                continue
            # Partition covers [first_of_month, first_of_next_month)
            # Drop it only when the entire range is older than cutoff.
            if month == 12:
                partition_end = date(year + 1, 1, 1)
            else:
                partition_end = date(year, month + 1, 1)
            if partition_end <= cutoff:
                cursor.execute(f'DROP TABLE IF EXISTS {pname}')
                dropped.append(pname)
        conn.commit()
    return dropped


def ensure_current_month_partition():
    """Public helper: guarantee the current month's partition exists."""
    with get_connection() as conn:
        cursor = conn.cursor()
        _ensure_month_partition(cursor, datetime.now().date())
        conn.commit()


# Initialize database on import
init_database()
