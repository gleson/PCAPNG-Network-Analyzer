"""
Celery configuration and tasks for async PCAP analysis.

Two queues:
  pcap.fast  — packet parsing, detection, DB save (CPU-bound, no external I/O)
  pcap.slow  — geolocation, threat intel (network-bound, can be slow)

Run workers targeting each queue:
  celery -A celery_app worker -Q pcap.fast --concurrency=2 -n fast@%h
  celery -A celery_app worker -Q pcap.slow --concurrency=4 -n slow@%h
  celery -A celery_app beat                               # for the retention purge
"""
import os
from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init
from pcap_analyzer import PCAPAnalyzer
import database as db


@worker_process_init.connect
def _init_worker_db_pool(**_kwargs):
    """Rebuild the DB connection pool in each prefork worker child.

    database.py is imported (and its pool may be created) in the Celery parent
    before it forks workers; a forked child cannot reuse those inherited
    connections. Resetting here means every child lazily builds its own pool on
    first query. See database.reset_pool / _get_pool for the rationale.
    """
    db.reset_pool()

# Initialize Celery
celery = Celery(
    'pcap_analyzer',
    broker=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Queue routing: analysis on fast, enrichment on slow
    task_routes={
        'pcap_analyzer.analyze_pcap':  {'queue': 'pcap.fast'},
        'pcap_analyzer.enrich_scan':   {'queue': 'pcap.slow'},
        'pcap_analyzer.retention_purge': {'queue': 'pcap.fast'},
    },
    # Periodic tasks (Celery Beat)
    beat_schedule={
        'daily-retention-purge': {
            'task': 'pcap_analyzer.retention_purge',
            'schedule': crontab(hour=3, minute=0),  # 03:00 UTC daily
        },
        'ensure-month-partition': {
            'task': 'pcap_analyzer.ensure_month_partition',
            'schedule': crontab(day_of_month=1, hour=0, minute=5),  # 1st of month
        },
    },
)


@celery.task(bind=True, name='pcap_analyzer.analyze_pcap')
def analyze_pcap_task(self, filepath, filename):
    """Fast-queue task: parse PCAP, run detections, save to DB, then hand off
    network-bound enrichment to the slow queue.

    Settings (which include API keys and SMTP creds) are loaded locally rather
    than passed as a task argument, so secrets never sit in the Redis broker.
    """
    try:
        from settings_store import load_settings
        settings = load_settings()

        # PCAPAnalyzer emite 0-100% durante analyze(). Aqui mapeamos para
        # 0-90% globais (deixando 90-100% para save/notify/enrich-dispatch).
        def progress_cb(progress, message, **meta):
            global_pct = max(0, min(90, int(progress * 0.9)))
            payload = {
                'progress': global_pct,
                'message': message,
                'filename': filename,
            }
            payload.update(meta)
            try:
                self.update_state(state='PROGRESS', meta=payload)
            except Exception as e:
                print(f"[analyze_pcap_task] update_state error: {e}")

        self.update_state(
            state='PROGRESS',
            meta={'progress': 0, 'message': 'Loading packets...',
                  'filename': filename, 'phase': 'starting'}
        )

        try:
            settings['device_types'] = {
                ip: (info.get('device_type') or 'Computador')
                for ip, info in db.get_all_ip_names().items()
            }
        except Exception:
            settings.setdefault('device_types', {})

        analyzer = PCAPAnalyzer(filepath, settings,
                                progress_callback=progress_cb)

        results = analyzer.analyze()

        self.update_state(
            state='PROGRESS',
            meta={'progress': 91, 'message': 'Running behavioral / correlation analysis...',
                  'filename': filename, 'phase': 'behavioral'}
        )

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

        self.update_state(
            state='PROGRESS',
            meta={'progress': 95, 'message': 'Saving to database...',
                  'filename': filename, 'phase': 'save_db'}
        )

        scan_id = db.save_scan(results, filename)

        try:
            from notifications import dispatch_alerts_for_scan
            dispatch_alerts_for_scan(scan_id, results, settings)
        except Exception as e:
            print(f"Notification dispatch error: {e}")

        # Dispatch enrichment (geo + threat intel) to the slow queue. Only the
        # scan_id crosses the broker — the slow task reloads the results blob
        # from the DB and its settings locally, keeping the large blob and any
        # secrets out of Redis.
        enrich_scan_task.apply_async(
            args=[scan_id],
            queue='pcap.slow',
        )

        self.update_state(
            state='PROGRESS',
            meta={'progress': 99, 'message': 'Enrichment dispatched to slow queue...',
                  'filename': filename, 'phase': 'enrich_dispatched'}
        )

        return {
            'status': 'completed',
            'scan_id': scan_id,
            'filename': filename,
        }

    except Exception as e:
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'filename': filename}
        )
        raise


@celery.task(name='pcap_analyzer.enrich_scan')
def enrich_scan_task(scan_id):
    """Slow-queue task: geolocation + IP/domain reputation + carved-file/YARA
    enrichment. Runs after the fast task completes, so the UI can show results
    immediately while enrichment continues in the background.

    Reloads the results blob from the DB (by scan_id) and settings locally
    instead of receiving them as task args, keeping the large blob and any
    secrets out of the Redis broker. Delegates to the shared pipeline
    (enrichment.run_enrichment) so this path cannot drift from the threading
    fallback; the enriched blob is persisted back to the scan.
    """
    try:
        results = db.get_scan_by_id(scan_id)
        if results is None:
            print(f"[enrich_scan] scan {scan_id} not found; skipping enrichment")
            return
        from settings_store import load_settings
        settings = load_settings()
        from enrichment import run_enrichment
        run_enrichment(scan_id, results, settings, persist=True)
        print(f"[enrich_scan] enrichment done for scan {scan_id}")
    except Exception as e:
        print(f"[enrich_scan] error for scan {scan_id}: {e}")


@celery.task(name='pcap_analyzer.retention_purge')
def retention_purge_task():
    """Periodic task: delete scans and alert partitions past the retention window.
    Retention days are read from data/settings.json (key: retention_days, default: 90).
    """
    try:
        import os
        import json as _json
        settings_file = os.environ.get('SETTINGS_FILE', 'data/settings.json')
        retention_days = 90
        try:
            with open(settings_file) as f:
                retention_days = int(_json.load(f).get('retention_days', 90))
        except Exception:
            pass
        deleted_scans = db.purge_old_scans(retention_days)
        dropped_parts = db.drop_old_partitions(retention_days)
        print(f"[retention_purge] deleted {deleted_scans} scans, "
              f"dropped {len(dropped_parts)} partitions (retention={retention_days}d)")
        # Reclaim disk: drop server-side PCAP copies + carved artifacts that no
        # surviving scan references. Never touches the user's source file (the
        # app only ever wrote the copy under UPLOAD_FOLDER). Isolated try so a
        # cleanup hiccup can't undo the DB purge above.
        try:
            upload_folder = os.environ.get('UPLOAD_FOLDER', 'data/uploads')
            cu = db.cleanup_orphaned_pcaps(upload_folder)
            print(f"[retention_purge] reclaimed {len(cu['removed_pcaps'])} "
                  f"orphaned pcap(s) + {len(cu['removed_artifact_dirs'])} "
                  f"artifact dir(s), freed {cu['freed_bytes']} bytes")
            if cu['errors']:
                print(f"[retention_purge] cleanup errors: {cu['errors'][:5]}")
        except Exception as ce:
            print(f"[retention_purge] orphan cleanup error: {ce}")
    except Exception as e:
        print(f"[retention_purge] error: {e}")


@celery.task(name='pcap_analyzer.ensure_month_partition')
def ensure_month_partition_task():
    """Periodic task: create the upcoming month's alerts partition on the 1st."""
    try:
        db.ensure_current_month_partition()
        print("[ensure_month_partition] partition ensured")
    except Exception as e:
        print(f"[ensure_month_partition] error: {e}")
