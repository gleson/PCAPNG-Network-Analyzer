"""
Shared helpers and module-level state for HTTP blueprints.

This module deliberately holds the few global things that used to live at the
top of app.py:
  - analysis_status / analysis_lock  (in-flight scan progress)
  - SETTINGS_FILE / UPLOAD_FOLDER / ALLOWED_EXTENSIONS
  - CELERY_AVAILABLE flag
  - settings JSON IO
  - audit_event flag-setter (read by app.py's after_request hook)
  - enrichment / geolocation / fallback analyze_pcap_background

Anything that wants to mutate the global analysis_status must do
`from routes import common` and then `common.analysis_status[...] = ...` so all
blueprints observe the same dict.
"""

import os
import threading
from datetime import datetime

import traceback

from flask import g, current_app, jsonify

import database as db


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'data/uploads')
# Settings file IO lives in settings_store (no Flask import) so the Celery
# workers can load settings locally; re-exported here for the blueprints.
from settings_store import (  # noqa: E402,F401
    SETTINGS_FILE, SETTINGS_EXAMPLE_FILE, load_settings, save_settings,
)
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
CELERY_AVAILABLE = bool(os.environ.get('CELERY_BROKER_URL'))


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

analysis_status = {
    "status": "idle",   # idle, analyzing, completed, error
    "progress": 0,
    "message": "",
    "filename": "",
    "scan_id": None,
    "task_id": None,
    "phase": "",
    "packet_count": 0,
    "elapsed_seconds": 0.0,
    "file_size": 0,
    "bytes_read": 0,
}

analysis_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Per-job status registry
# ---------------------------------------------------------------------------
# Multiple analyses can run concurrently (the old single global dict allowed
# only ONE in-flight scan app-wide, blocking multi-user uploads). Each upload
# is tracked by its own id so callers can poll just their job:
#   - Celery mode (CELERY_AVAILABLE): id == Celery task id; live progress comes
#     from Celery's result backend, this registry only remembers the filename.
#   - threading fallback: id == generated job id; this registry IS the source
#     of truth, written by analyze_pcap_background.
# analysis_status above is kept only as the "latest" snapshot for legacy callers
# that hit /api/status without a task_id.
analysis_jobs = {}                 # job_id -> status dict
analysis_jobs_lock = threading.Lock()
MAX_TRACKED_JOBS = 64              # bound registry growth (drop oldest)


def new_status(filename="", task_id=None):
    """A fresh 'analyzing' status dict with the canonical field set."""
    return {
        "status": "analyzing",
        "progress": 0,
        "message": "Starting analysis...",
        "filename": filename,
        "scan_id": None,
        "task_id": task_id,
        "phase": "starting",
        "packet_count": 0,
        "elapsed_seconds": 0.0,
        "file_size": 0,
        "bytes_read": 0,
    }


def _mirror_latest(snapshot):
    """Mirror *snapshot* into the legacy global so no-task_id callers see it."""
    with analysis_lock:
        analysis_status.clear()
        analysis_status.update(snapshot)


def register_job(job_id, filename, task_id=None):
    """Create a registry entry for a freshly started analysis and mark it the
    latest. Returns the stored snapshot dict (a copy)."""
    entry = new_status(filename, task_id or job_id)
    with analysis_jobs_lock:
        analysis_jobs[job_id] = entry
        if len(analysis_jobs) > MAX_TRACKED_JOBS:
            # drop oldest insertion-order entries
            for stale in list(analysis_jobs)[:-MAX_TRACKED_JOBS]:
                analysis_jobs.pop(stale, None)
    _mirror_latest(entry)
    return dict(entry)


def get_job(job_id):
    """Return a copy of the registry entry for *job_id*, or None."""
    with analysis_jobs_lock:
        entry = analysis_jobs.get(job_id)
        return dict(entry) if entry else None


def set_job(job_id, snapshot):
    """Replace the registry entry for *job_id* and mirror it as latest if it is
    the one the global currently points at."""
    with analysis_jobs_lock:
        if job_id in analysis_jobs:
            analysis_jobs[job_id] = dict(snapshot)
    with analysis_lock:
        is_latest = analysis_status.get("task_id") == snapshot.get("task_id")
    if is_latest:
        _mirror_latest(snapshot)


def update_job(job_id, **fields):
    """Patch fields on a registry entry (used by the threading fallback)."""
    with analysis_jobs_lock:
        entry = analysis_jobs.get(job_id)
        if entry is None:
            entry = analysis_jobs[job_id] = new_status(task_id=job_id)
        entry.update(fields)
        snapshot = dict(entry)
    with analysis_lock:
        is_latest = analysis_status.get("task_id") == snapshot.get("task_id")
    if is_latest:
        _mirror_latest(snapshot)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

AUDIT_MUTATING_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}
AUDIT_PATH_BLOCKLIST_PREFIXES = ('/api/status',)


def audit_event(action=None, target_type=None, target_id=None, extra=None):
    """Tag the current request so the audit after_request hook records it."""
    g.audit_action = action
    g.audit_target_type = target_type
    g.audit_target_id = target_id
    if extra is not None:
        g.audit_extra = extra


# ---------------------------------------------------------------------------
# Error responses
# ---------------------------------------------------------------------------

def server_error(exc):
    """Log an unexpected exception server-side and return a generic 500.

    Raw exception text (filesystem paths, SQL fragments, library internals)
    must never reach the client — it is reconnaissance for an attacker. The
    full detail goes to the server log; the caller gets an opaque message.
    """
    traceback.print_exc()
    return jsonify({"success": False, "error": "internal server error"}), 500


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_folder():
    """Resolve upload folder from app config when available, else env constant."""
    try:
        return current_app.config['UPLOAD_FOLDER']
    except RuntimeError:
        return UPLOAD_FOLDER


# load_settings / save_settings now live in settings_store (imported above).


# ---------------------------------------------------------------------------
# Result enrichment
# ---------------------------------------------------------------------------

def enrich_results_with_names_and_groups(results, settings):
    """Add per-IP name/group/geolocation/reputation fields in place."""
    ip_names = db.get_all_ip_names()
    ip_geos = db.get_all_ip_geolocations()
    ip_reps = db.get_all_ip_reputations()
    trusted_ranges = settings.get('trusted_ranges', [])

    for ip_data in results.get('ips', []):
        ip_addr = ip_data.get('ip')

        ip_info = ip_names.get(ip_addr, {})
        ip_data['name'] = ip_info.get('name', '')

        group = db.get_ip_in_range(ip_addr, trusted_ranges)
        ip_data['group'] = group or ''

        geo = ip_geos.get(ip_addr)
        if geo:
            ip_data['geolocation'] = geo

        rep = ip_reps.get(ip_addr)
        if rep:
            ip_data['reputation'] = rep

    protocol_ips = results.get('protocol_ips', {})
    for proto_name, ip_list in protocol_ips.items():
        for ip_data in ip_list:
            ip_addr = ip_data.get('ip')
            ip_info = ip_names.get(ip_addr, {})
            ip_data['name'] = ip_info.get('name', '')

    try:
        from host_risk import compute_host_risk_scores
        compute_host_risk_scores(results)
    except Exception as e:
        print(f"[routes/common] host_risk recompute failed: {e}")

    return results


def merge_alert_triage_state(results, scan_id):
    """
    Splice DB triage state into the results['alerts'] JSON blob.

    The alerts inside results_json are point-in-time snapshots without DB ids;
    the DB alerts table is the source of truth for triage. save_scan() inserts
    alerts in the same order they appear in the JSON blob, so we can merge by
    index — preserving blob-only fields (e.g. mitre_attack).
    """
    blob_alerts = results.get('alerts') or []
    try:
        db_alerts = db.get_alerts_by_scan(scan_id, order='id')
    except Exception as e:
        print(f"[app] could not load triage state for scan {scan_id}: {e}")
        return results

    if len(db_alerts) == len(blob_alerts):
        for blob_alert, db_alert in zip(blob_alerts, db_alerts):
            blob_alert['id'] = db_alert['id']
            blob_alert['triage_status'] = db_alert['triage_status']
            blob_alert['triage_note'] = db_alert.get('triage_note')
            blob_alert['triaged_at'] = db_alert.get('triaged_at')
    else:
        print(f"[app] alert count mismatch for scan {scan_id}: "
              f"{len(blob_alerts)} blob vs {len(db_alerts)} db")
        results['alerts'] = db_alerts

    try:
        results['alert_status_counts'] = db.get_alert_status_counts(scan_id)
    except Exception as e:
        print(f"[app] could not load alert status counts for scan {scan_id}: {e}")
    return results


def analyze_pcap_background(filepath, filename, job_id):
    """Threading-based fallback used when Celery is not available.

    Writes progress to the per-job registry entry (``job_id``) so several
    fallback analyses can be tracked independently.
    """
    from pcap_analyzer import PCAPAnalyzer

    def progress_cb(progress, message, **meta):
        global_pct = max(0, min(90, int(progress * 0.9)))
        update_job(
            job_id,
            status="analyzing",
            progress=global_pct,
            message=message,
            filename=filename,
            phase=meta.get('phase', ''),
            packet_count=meta.get('packet_count', 0),
            elapsed_seconds=meta.get('elapsed_seconds', 0.0),
            file_size=meta.get('file_size', 0),
            bytes_read=meta.get('bytes_read', 0),
        )

    try:
        update_job(job_id, status="analyzing", progress=0,
                   message="Loading packets...", filename=filename,
                   scan_id=None, phase="starting", packet_count=0,
                   elapsed_seconds=0.0)

        settings = load_settings()
        try:
            settings['device_types'] = {
                ip: (info.get('device_type') or 'Computador')
                for ip, info in db.get_all_ip_names().items()
            }
        except Exception:
            settings['device_types'] = {}
        analyzer = PCAPAnalyzer(filepath, settings,
                                progress_callback=progress_cb)

        results = analyzer.analyze()

        update_job(job_id, progress=91, phase="behavioral",
                   message="Running behavioral baseline analysis...")

        try:
            from behavioral import analyze_behavioral_baseline
            analyze_behavioral_baseline(results, settings)
        except Exception as e:
            print(f"Behavioral analysis error: {e}")

        try:
            from correlation import detect_new_artifacts, correlate_intra_scan
            detect_new_artifacts(results, settings)
            correlate_intra_scan(results, settings)
        except Exception as e:
            print(f"Correlation analysis error: {e}")

        update_job(job_id, progress=93, phase="save_db",
                   message="Saving to database...")

        scan_id = db.save_scan(results, filename)

        try:
            from notifications import dispatch_alerts_for_scan
            dispatch_alerts_for_scan(scan_id, results, settings)
        except Exception as e:
            print(f"Notification dispatch error: {e}")

        update_job(job_id, progress=95, phase="enrich",
                   message="Enriching (geo / reputation / YARA)...")

        # Same enrichment pipeline as the Celery slow queue (single source of
        # truth — see enrichment.run_enrichment). It persists the enriched blob
        # back to the scan, so there is no need to re-save here.
        from enrichment import run_enrichment
        run_enrichment(scan_id, results, settings, persist=True)

        update_job(job_id, status="completed", progress=100, phase="done",
                   message="Analysis completed successfully", scan_id=scan_id)

    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        update_job(job_id, status="error", phase="error", message=str(e))
