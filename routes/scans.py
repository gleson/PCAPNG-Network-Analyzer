"""
Scan lifecycle: upload, status, results, packet viewer, replay, diff, report,
carved-file artifacts, STIX/MISP export.
---
tags: [Scans]
"""

import os
import json
import time
import uuid
import tempfile
import threading
from datetime import datetime

from flask import Blueprint, request, jsonify, Response, current_app, stream_with_context
from werkzeug.utils import secure_filename

import database as db
from auth import role_required

from . import common
from .common import (
    audit_event, allowed_file, load_settings,
    enrich_results_with_names_and_groups, merge_alert_triage_state,
    analysis_lock, analyze_pcap_background, CELERY_AVAILABLE, server_error,
)


scans_bp = Blueprint('scans', __name__)


@scans_bp.route('/api/upload', methods=['POST'])
@role_required('analyst')
def upload_file():
    """
    Upload a PCAP/PCAPNG file and start analysis (Celery or threading fallback).
    ---
    tags: [Scans]
    requestBody:
      required: true
      content:
        multipart/form-data:
          schema:
            type: object
            properties:
              file:
                type: string
                format: binary
    responses:
      200: {description: Upload accepted, analysis started}
      400: {description: Validation error}
    """
    # No app-level single-flight gate: concurrency is bounded by the Celery
    # worker pool (pcap.fast) in production, or simply by available threads in
    # the fallback. Each upload is tracked by its own task_id so multiple users
    # can analyse at once.
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Invalid file type. Only .pcap and .pcapng files are allowed"}), 400

    try:
        filename = secure_filename(file.filename or '')
        # secure_filename returns '' when the input is purely path/control
        # characters; also re-check the extension because the sanitizer can
        # strip the original (e.g. "..pcap" → "pcap" — no extension left).
        if not filename or not allowed_file(filename):
            return jsonify({
                "success": False,
                "error": "Invalid filename after sanitization"
            }), 400

        upload_root = os.path.realpath(current_app.config['UPLOAD_FOLDER'])
        os.makedirs(upload_root, exist_ok=True)
        filepath = os.path.realpath(os.path.join(upload_root, filename))
        # Defense-in-depth: refuse anything that escapes the upload root.
        if os.path.commonpath([upload_root, filepath]) != upload_root \
                or os.path.dirname(filepath) != upload_root:
            return jsonify({
                "success": False,
                "error": "Filename rejected: would escape upload directory"
            }), 400

        file.save(filepath)

        audit_event(action='upload_pcap', target_type='pcap', target_id=filename,
                    extra={'size': os.path.getsize(filepath)})

        if CELERY_AVAILABLE:
            from celery_app import analyze_pcap_task
            # Settings are loaded by the worker (not shipped as a task arg) so
            # API keys / SMTP creds never sit in the Redis broker.
            task = analyze_pcap_task.apply_async(args=[filepath, filename])
            task_id = task.id
            # Live progress comes from Celery's backend; the registry just
            # remembers the filename and marks this the latest job.
            common.register_job(task_id, filename, task_id=task_id)
        else:
            task_id = uuid.uuid4().hex
            common.register_job(task_id, filename, task_id=task_id)
            thread = threading.Thread(
                target=analyze_pcap_background,
                args=(filepath, filename, task_id)
            )
            thread.daemon = True
            thread.start()

        return jsonify({
            "success": True,
            "message": "File uploaded successfully. Analysis started.",
            "filename": filename,
            "task_id": task_id
        })

    except Exception as e:
        return server_error(e)


def _refresh_status_snapshot(task_id=None):
    """
    Return a fresh status snapshot for a specific *task_id*. When *task_id* is
    omitted, report the most-recent ("latest") analysis — kept for legacy
    callers that hit /api/status without an id.

    In Celery mode live progress is read from the result backend (so every
    task_id is independently pollable, enabling concurrent analyses); in the
    threading fallback the per-job registry is the source of truth.
    """
    if not task_id:
        with analysis_lock:
            task_id = common.analysis_status.get("task_id")
            latest = dict(common.analysis_status)
        if not task_id:
            return latest

    if not CELERY_AVAILABLE:
        snap = common.get_job(task_id)
        return snap or {"status": "idle", "progress": 0, "message": "",
                        "filename": "", "scan_id": None, "task_id": None,
                        "phase": ""}

    from celery_app import analyze_pcap_task
    task = analyze_pcap_task.AsyncResult(task_id)

    snap = common.get_job(task_id) or common.new_status(task_id=task_id)
    state = task.state

    if state == 'PROGRESS':
        meta = task.info or {}
        snap.update({
            "status": "analyzing",
            "progress": meta.get('progress', 0),
            "message": meta.get('message', ''),
            "phase": meta.get('phase', ''),
            "packet_count": meta.get('packet_count', 0),
            "elapsed_seconds": meta.get('elapsed_seconds', 0.0),
            "file_size": meta.get('file_size', 0),
            "bytes_read": meta.get('bytes_read', 0),
            "filename": meta.get('filename', snap.get('filename', '')),
        })
    elif state == 'SUCCESS':
        result = task.result or {}
        snap.update({
            "status": "completed",
            "progress": 100,
            "message": "Analysis completed successfully",
            "scan_id": result.get('scan_id'),
            "filename": result.get('filename', snap.get('filename', '')),
            "phase": "done",
        })
    elif state == 'FAILURE':
        snap.update({
            "status": "error",
            "message": str(task.info) if task.info else 'Unknown error',
            "phase": "error",
        })
    elif common.get_job(task_id) is None:
        # PENDING/unknown id with no registry entry → nothing in flight.
        snap["status"] = "idle"
    # else PENDING/STARTED for a known job: keep the registered "analyzing".

    common.set_job(task_id, snap)
    return snap


@scans_bp.route('/api/status', methods=['GET'])
def get_status():
    """
    Get a one-shot snapshot of the in-flight analysis status.

    Kept for callers that cannot use SSE (curl, tests, debugging). Browsers
    should prefer /api/status/stream which pushes updates in real time. Pass
    ?task_id=<id> to poll a specific analysis; omit it for the latest one.
    ---
    tags: [Scans]
    parameters:
      - in: query
        name: task_id
        schema: {type: string}
    responses:
      200: {description: Current status snapshot}
    """
    return jsonify(_refresh_status_snapshot(request.args.get('task_id') or None))


@scans_bp.route('/api/status/stream', methods=['GET'])
def stream_status():
    """
    Server-Sent Events feed for the in-flight analysis status.

    Replaces the old setInterval polling on /api/status. Each `data:` frame
    is the same JSON payload as /api/status; the stream closes after a
    terminal state ('completed' or 'error') is delivered.
    ---
    tags: [Scans]
    parameters:
      - in: query
        name: task_id
        schema: {type: string}
    responses:
      200:
        description: text/event-stream of status updates
        content:
          text/event-stream: {}
    """
    # Bind the requested task_id before leaving the request context (the
    # generator below runs outside it).
    task_id = request.args.get('task_id') or None

    # 500ms server-side tick matches the old client polling cadence; a
    # heartbeat comment is emitted every iteration so reverse proxies do
    # not buffer or drop the connection during idle stretches.
    POLL_SECONDS = 0.5
    # Cap stream lifetime so a stuck/forgotten connection eventually frees
    # the worker thread even if the client never disconnects.
    MAX_DURATION_SECONDS = 60 * 60

    @stream_with_context
    def event_stream():
        last_payload = None
        terminal_sent = False
        started = time.monotonic()
        while True:
            snapshot = _refresh_status_snapshot(task_id)
            payload = json.dumps(snapshot, default=str)
            if payload != last_payload:
                yield f"data: {payload}\n\n"
                last_payload = payload
            else:
                # Keep-alive comment — ignored by EventSource but keeps
                # intermediaries (nginx, Vite proxy) from closing the
                # connection on idle.
                yield ": keep-alive\n\n"

            if snapshot.get("status") in ("completed", "error"):
                if terminal_sent:
                    break
                terminal_sent = True

            if time.monotonic() - started > MAX_DURATION_SECONDS:
                break

            time.sleep(POLL_SECONDS)

    resp = Response(event_stream(), mimetype='text/event-stream')
    resp.headers['Cache-Control'] = 'no-cache, no-transform'
    resp.headers['X-Accel-Buffering'] = 'no'      # disable nginx buffering
    resp.headers['Connection'] = 'keep-alive'
    return resp


@scans_bp.route('/api/results', methods=['GET'])
def get_results():
    """
    Return scan results: latest (no params), specific scan_id, or aggregated view.
    ---
    tags: [Scans]
    parameters:
      - in: query
        name: scan_id
        schema: {type: integer}
      - in: query
        name: view
        schema: {type: string, enum: [single, aggregate]}
      - in: query
        name: scan_ids
        schema: {type: string}
        description: Comma-separated scan ids for aggregate view
      - in: query
        name: date_from
        schema: {type: string, format: date}
      - in: query
        name: date_to
        schema: {type: string, format: date}
    """
    scan_id = request.args.get('scan_id', type=int)
    view = request.args.get('view', 'single')
    scan_ids_param = request.args.get('scan_ids', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    settings = load_settings()

    try:
        if view == 'aggregate':
            scan_ids = None
            if scan_ids_param:
                scan_ids = [int(x) for x in scan_ids_param.split(',')]

            results = db.get_aggregated_results(
                scan_ids,
                settings.get('trusted_ranges', []),
                date_from=date_from or None,
                date_to=date_to or None
            )

            if not results['ips']:
                return jsonify({"success": False, "error": "No analysis results available"}), 404

            return jsonify({"success": True, "data": results, "view": "aggregate"})

        elif scan_id:
            results = db.get_scan_by_id(scan_id)
            if not results:
                return jsonify({"success": False, "error": "Scan not found"}), 404

            results = enrich_results_with_names_and_groups(results, settings)
            results = merge_alert_triage_state(results, scan_id)
            return jsonify({"success": True, "data": results, "scan_id": scan_id, "view": "single"})

        else:
            latest_id = db.get_latest_scan_id()
            if latest_id is None:
                return jsonify({"success": False, "error": "No analysis results available"}), 404

            results = db.get_scan_by_id(latest_id)
            if results is None:
                return jsonify({"success": False, "error": "No analysis results available"}), 404

            results = enrich_results_with_names_and_groups(results, settings)
            results = merge_alert_triage_state(results, latest_id)
            return jsonify({"success": True, "data": results, "scan_id": latest_id, "view": "single"})

    except Exception as e:
        print(f"Error getting results: {e}")
        import traceback
        traceback.print_exc()
        return server_error(e)


@scans_bp.route('/api/scans', methods=['GET'])
def get_scans():
    """
    List all scans (optionally filtered by date range).
    ---
    tags: [Scans]
    parameters:
      - in: query
        name: date_from
        schema: {type: string}
      - in: query
        name: date_to
        schema: {type: string}
    """
    try:
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        scans = db.get_all_scans(
            date_from=date_from or None,
            date_to=date_to or None
        )
        return jsonify({"success": True, "data": scans})
    except Exception as e:
        return server_error(e)


@scans_bp.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@role_required('analyst')
def delete_scan(scan_id):
    """
    Delete a scan record. The source PCAP file is kept on disk.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
    """
    try:
        filename = db.delete_scan(scan_id)
        if filename:
            # Only the database record is removed; the source PCAP file
            # is intentionally left on disk.
            audit_event(action='delete_scan', target_type='scan', target_id=scan_id,
                        extra={'filename': filename})
            return jsonify({"success": True, "message": "Scan excluído com sucesso"})
        else:
            return jsonify({"success": False, "error": "Scan not found"}), 404
    except Exception as e:
        return server_error(e)


@scans_bp.route('/api/scans/batch', methods=['DELETE'])
@role_required('analyst')
def delete_multiple_scans():
    """
    Delete multiple scan records. The source PCAP files are kept on disk.
    ---
    tags: [Scans]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              ids: {type: array, items: {type: integer}}
    """
    try:
        data = request.get_json()
        scan_ids = data.get('ids', [])
        if not scan_ids:
            return jsonify({"success": False, "error": "Nenhum scan selecionado"}), 400

        # Only the database records are removed; the source PCAP files
        # are intentionally left on disk.
        filenames = db.delete_multiple_scans(scan_ids)

        audit_event(action='delete_scans_batch', target_type='scan',
                    target_id=','.join(str(i) for i in scan_ids),
                    extra={'count': len(filenames)})

        return jsonify({
            "success": True,
            "message": f"{len(filenames)} scan(s) excluído(s) com sucesso",
            "deleted_count": len(filenames)
        })
    except Exception as e:
        return server_error(e)


@scans_bp.route('/api/clear', methods=['POST'])
@role_required('analyst')
def clear_analysis():
    """
    Clear the in-memory analysis state.
    ---
    tags: [Scans]
    """
    try:
        with analysis_lock:
            if common.analysis_status["status"] == "analyzing":
                return jsonify({"success": False, "error": "Cannot clear while analysis is in progress"}), 400

            common.analysis_status.clear()
            common.analysis_status.update({
                "status": "idle", "progress": 0, "message": "",
                "filename": "", "scan_id": None, "task_id": None,
            })

        return jsonify({"success": True, "message": "Analysis cleared"})
    except Exception as e:
        return server_error(e)


# ===== PACKET VIEWER =====

@scans_bp.route('/api/packets/<int:scan_id>', methods=['GET'])
def get_packets(scan_id):
    """
    Get paginated packets from a scan's PCAP file.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
      - in: query
        name: page
        schema: {type: integer, default: 1}
      - in: query
        name: per_page
        schema: {type: integer, maximum: 200, default: 50}
      - in: query
        name: filter_ip
        schema: {type: string}
      - in: query
        name: filter_protocol
        schema: {type: string}
    """
    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        filename = scan['summary']['filename']
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(filepath):
            return jsonify({"success": False, "error": "PCAP file not found on disk"}), 404

        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        filter_ip = request.args.get('filter_ip', '')
        filter_protocol = request.args.get('filter_protocol', '').upper()

        from packet_index import get_packet_index, matches as _pkt_matches, public_view

        # Parse the PCAP once into a cached compact index; paging/filtering then
        # runs in pure Python (no scapy re-parse on subsequent pages).
        index = get_packet_index(filepath)
        filtered = [e for e in index if _pkt_matches(e, filter_ip, filter_protocol)]

        total = len(filtered)
        start = (page - 1) * per_page
        packet_list = [public_view(e) for e in filtered[start:start + per_page]]

        return jsonify({
            "success": True,
            "data": {
                "packets": packet_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": max(1, (total + per_page - 1) // per_page)
            }
        })

    except Exception as e:
        print(f"Error reading packets: {e}")
        import traceback
        traceback.print_exc()
        return server_error(e)


@scans_bp.route('/api/packets/<int:scan_id>/<int:packet_num>', methods=['GET'])
def get_packet_detail(scan_id, packet_num):
    """
    Detailed dissection + hex dump for a single packet.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
      - in: path
        name: packet_num
        schema: {type: integer}
        required: true
    """
    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        filename = scan['summary']['filename']
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(filepath):
            return jsonify({"success": False, "error": "PCAP file not found"}), 404

        from scapy.all import PcapReader
        from packet_index import MAX_VIEWER_PKTS

        idx = packet_num - 1
        if idx < 0 or idx >= MAX_VIEWER_PKTS:
            return jsonify({"success": False, "error": "Invalid packet number"}), 404

        # Stream and stop at the target packet — no need to materialise the
        # whole capture just to index one packet.
        pkt = None
        with PcapReader(filepath) as _reader:
            for _i, _p in enumerate(_reader):
                if _i == idx:
                    pkt = _p
                    break
                if _i >= MAX_VIEWER_PKTS:
                    break

        if pkt is None:
            return jsonify({"success": False, "error": "Invalid packet number"}), 404

        layers = []
        layer = pkt
        while layer:
            layer_info = {
                'name': layer.__class__.__name__,
                'fields': {}
            }
            for field in layer.fields_desc:
                val = layer.getfieldval(field.name)
                if isinstance(val, bytes):
                    if len(val) <= 50:
                        val = val.hex()
                    else:
                        val = val[:50].hex() + f'... ({len(val)} bytes)'
                else:
                    val = str(val)
                layer_info['fields'][field.name] = val
            layers.append(layer_info)
            layer = layer.payload if layer.payload and not isinstance(layer.payload, bytes) else None

        raw_bytes = bytes(pkt)
        hex_lines = []
        for offset in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[offset:offset + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f'{offset:04x}  {hex_part:<48}  {ascii_part}')

        return jsonify({
            "success": True,
            "data": {
                'number': packet_num,
                'summary': pkt.summary(),
                'layers': layers,
                'hexdump': '\n'.join(hex_lines),
                'length': len(pkt)
            }
        })

    except Exception as e:
        return server_error(e)


@scans_bp.route('/api/replay/<int:scan_id>', methods=['GET'])
@role_required('analyst')
def replay_filtered_pcap(scan_id):
    """
    Apply a BPF filter on the scan's PCAP and return the filtered subset as a .pcap.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
      - in: query
        name: bpf
        schema: {type: string, maxLength: 256}
        required: true
      - in: query
        name: max_packets
        schema: {type: integer, default: 100000}
    """
    bpf = (request.args.get('bpf') or '').strip()
    if not bpf:
        return jsonify({"success": False, "error": "bpf query param required"}), 400
    if len(bpf) > 256:
        return jsonify({"success": False, "error": "bpf too long (>256)"}), 400
    if any(not (32 <= ord(c) < 127) for c in bpf):
        return jsonify({"success": False, "error": "bpf contains non-ASCII / control bytes"}), 400

    try:
        max_packets = min(int(request.args.get('max_packets', 100000)), 1_000_000)
    except (TypeError, ValueError):
        max_packets = 100000

    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "scan not found"}), 404
        filename = (scan.get('summary') or {}).get('filename')
        if not filename:
            return jsonify({"success": False, "error": "scan has no source filename"}), 404
        src_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(src_path):
            return jsonify({"success": False, "error": "source PCAP not found on disk"}), 404

        from scapy.all import sniff, wrpcap
        try:
            filtered = sniff(offline=src_path, filter=bpf, count=max_packets)
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"BPF filter failed (libpcap may be missing or expression invalid): {e}",
            }), 400

        if not filtered:
            return jsonify({"success": False, "error": "filter matched 0 packets"}), 404

        # mkstemp creates the file atomically with O_EXCL and 0600 perms in
        # the system temp dir — no predictable name, no symlink race.
        fd, out_path = tempfile.mkstemp(prefix=f'replay_{scan_id}_', suffix='.pcap')
        os.close(fd)
        try:
            wrpcap(out_path, filtered)
            with open(out_path, 'rb') as f:
                data = f.read()
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass

        download_name = f"scan_{scan_id}_replay_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        audit_event(action='replay_pcap', target_type='scan', target_id=scan_id,
                    extra={'bpf': bpf, 'matched_packets': len(filtered)})
        return Response(
            data,
            mimetype='application/vnd.tcpdump.pcap',
            headers={
                'Content-Disposition': f'attachment; filename={download_name}',
                'X-Matched-Packets': str(len(filtered)),
            },
        )
    except Exception as e:
        return server_error(e)


@scans_bp.route('/api/diff', methods=['GET'])
def diff_scans():
    """
    Compare two scans by IP set / protocols / alert titles / artifacts.
    ---
    tags: [Scans]
    parameters:
      - in: query
        name: a
        schema: {type: integer}
        required: true
        description: Base scan id
      - in: query
        name: b
        schema: {type: integer}
        required: true
        description: Target scan id
    """
    try:
        a_id = int(request.args.get('a', ''))
        b_id = int(request.args.get('b', ''))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "a and b (scan ids) required"}), 400
    try:
        a = db.get_scan_by_id(a_id)
        b = db.get_scan_by_id(b_id)
    except Exception as e:
        return server_error(e)
    if not a or not b:
        return jsonify({"success": False, "error": "scan not found"}), 404

    def _ip_set(scan):
        return {ip['ip'] for ip in (scan.get('ips') or []) if ip.get('ip')}

    def _proto_set(scan):
        return {p['name'] for p in (scan.get('protocols') or []) if p.get('name')}

    def _alert_titles(scan):
        return {a.get('title') for a in (scan.get('alerts') or []) if a.get('title')}

    def _artifacts(scan, key):
        return set((scan.get('observed_artifacts') or {}).get(key) or [])

    def _diff(set_a, set_b):
        return {
            'added':   sorted(set_b - set_a),
            'removed': sorted(set_a - set_b),
            'common':  len(set_a & set_b),
        }

    sev_count = lambda scan: {  # noqa: E731
        s: sum(1 for x in (scan.get('alerts') or []) if x.get('severity') == s)
        for s in ('critical', 'high', 'medium', 'low')
    }

    payload = {
        "a": {"scan_id": a_id, "filename": (a.get('summary') or {}).get('filename'),
              "analyzed_at": (a.get('summary') or {}).get('analyzed_at'),
              "alert_severity_counts": sev_count(a)},
        "b": {"scan_id": b_id, "filename": (b.get('summary') or {}).get('filename'),
              "analyzed_at": (b.get('summary') or {}).get('analyzed_at'),
              "alert_severity_counts": sev_count(b)},
        "ips":          _diff(_ip_set(a), _ip_set(b)),
        "protocols":    _diff(_proto_set(a), _proto_set(b)),
        "alert_titles": _diff(_alert_titles(a), _alert_titles(b)),
        "artifacts": {
            k: _diff(_artifacts(a, k), _artifacts(b, k))
            for k in ('ja3', 'ja3s', 'sni', 'http_host', 'mac')
        },
    }
    return jsonify({"success": True, "diff": payload})


@scans_bp.route('/api/scans/<int:scan_id>/export', methods=['GET'])
@role_required('analyst')
def export_scan(scan_id):
    """
    Export a scan's IOCs. ?format=stix (default) or ?format=misp.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
      - in: query
        name: format
        schema: {type: string, enum: [stix, misp], default: stix}
    """
    fmt = (request.args.get('format', 'stix') or 'stix').lower()
    if fmt not in ('stix', 'misp'):
        return jsonify({"success": False, "error": "format must be 'stix' or 'misp'"}), 400
    try:
        results = db.get_scan_by_id(scan_id)
        if not results:
            return jsonify({"success": False, "error": "scan not found"}), 404
        from stix_export import to_stix_bundle, to_misp_event
        payload = to_stix_bundle(results, scan_id) if fmt == 'stix' else to_misp_event(results, scan_id)
        filename = f"scan_{scan_id}_{fmt}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        body = json.dumps(payload, indent=2)
        audit_event(action='export_scan', target_type='scan', target_id=scan_id,
                    extra={'format': fmt})
        return Response(
            body,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}'},
        )
    except Exception as e:
        return server_error(e)


@scans_bp.route('/api/report/<int:scan_id>', methods=['GET'])
def generate_report(scan_id):
    """
    Generate PDF or HTML report for a scan.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
      - in: query
        name: format
        schema: {type: string, enum: [pdf, html], default: pdf}
    """
    try:
        results = db.get_scan_by_id(scan_id)
        if not results:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        # Splice in DB alert ids so the report can print a trackable ID column.
        results = merge_alert_triage_state(results, scan_id)
        settings = load_settings()
        results = enrich_results_with_names_and_groups(results, settings)

        report_format = request.args.get('format', 'pdf').lower()

        from report_generator import generate_pdf_report, generate_html_report

        if report_format == 'html':
            html_content = generate_html_report(results)
            filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            return Response(
                html_content,
                mimetype='text/html',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
        else:
            # Secure temp file: atomic O_EXCL create, 0600, random name.
            fd, output_path = tempfile.mkstemp(prefix=f'report_{scan_id}_',
                                               suffix='.pdf')
            os.close(fd)
            try:
                generate_pdf_report(results, output_path)
                with open(output_path, 'rb') as f:
                    pdf_data = f.read()
            finally:
                try:
                    os.remove(output_path)
                except OSError:
                    pass

            filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            return Response(
                pdf_data,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )

    except Exception as e:
        print(f"Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return server_error(e)


@scans_bp.route('/api/scans/<int:scan_id>/alerts-report', methods=['GET'])
def generate_alerts_report(scan_id):
    """
    Generate a PDF report listing every security alert for a scan.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
    """
    try:
        results = db.get_scan_by_id(scan_id)
        if not results:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        # Splice in DB alert ids so the report can print a trackable ID column.
        results = merge_alert_triage_state(results, scan_id)
        settings = load_settings()
        results = enrich_results_with_names_and_groups(results, settings)

        from report_generator import generate_alerts_pdf_report

        # Secure temp file: atomic O_EXCL create, 0600, random name.
        fd, output_path = tempfile.mkstemp(prefix=f'alerts_{scan_id}_',
                                           suffix='.pdf')
        os.close(fd)
        try:
            generate_alerts_pdf_report(results, output_path)
            with open(output_path, 'rb') as f:
                pdf_data = f.read()
        finally:
            try:
                os.remove(output_path)
            except OSError:
                pass

        filename = f"alerts_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        audit_event(action='export_alerts_report', target_type='scan',
                    target_id=scan_id, extra={'format': 'pdf'})
        return Response(
            pdf_data,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )

    except Exception as e:
        print(f"Error generating alerts report: {e}")
        import traceback
        traceback.print_exc()
        return server_error(e)


@scans_bp.route('/api/scans/<int:scan_id>/killchain', methods=['GET'])
def killchain_view(scan_id):
    """
    Per-host MITRE ATT&CK kill-chain timeline for a scan.

    Groups every alert by source host, then by MITRE tactic, preserving alert
    ordering for an at-a-glance lifecycle view (Recon → Initial Access → ... →
    Impact). The frontend renders one swimlane per host with severity-coloured
    markers placed in the matching tactic column.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
    responses:
      200: {description: Kill-chain matrix}
      404: {description: Scan not found}
    """
    # MITRE kill-chain order used for the Y/column layout. Only tactics we
    # actually emit (mitre_attack.py::TACTICS) plus Execution (TA0002), which
    # appears in some user-rule mappings, are listed; anything else falls into
    # an 'OTHER' bucket so the view never silently drops alerts.
    TACTIC_ORDER = [
        'TA0043',  # Reconnaissance
        'TA0001',  # Initial Access
        'TA0002',  # Execution
        'TA0007',  # Discovery
        'TA0006',  # Credential Access
        'TA0008',  # Lateral Movement
        'TA0011',  # Command and Control
        'TA0010',  # Exfiltration
        'TA0040',  # Impact
    ]
    TACTIC_LABELS = {
        'TA0043': {'name': 'Reconnaissance',    'short': 'Recon'},
        'TA0001': {'name': 'Initial Access',    'short': 'Init Access'},
        'TA0002': {'name': 'Execution',         'short': 'Execution'},
        'TA0007': {'name': 'Discovery',         'short': 'Discovery'},
        'TA0006': {'name': 'Credential Access', 'short': 'Cred Access'},
        'TA0008': {'name': 'Lateral Movement',  'short': 'Lateral'},
        'TA0011': {'name': 'Command and Control', 'short': 'C2'},
        'TA0010': {'name': 'Exfiltration',      'short': 'Exfil'},
        'TA0040': {'name': 'Impact',            'short': 'Impact'},
        'OTHER':  {'name': 'Other',             'short': 'Other'},
    }
    SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "scan not found"}), 404

        settings = load_settings()
        scan = enrich_results_with_names_and_groups(scan, settings)

        alerts = scan.get('alerts') or []
        # Build a quick IP → display name map from the enriched IPs list.
        ip_meta = {}
        for ip_row in (scan.get('ips') or []):
            ip = ip_row.get('ip')
            if ip:
                ip_meta[ip] = {
                    'name': ip_row.get('name') or '',
                    'group': ip_row.get('group') or '',
                    'is_local': bool(ip_row.get('is_local')),
                    'device_type': ip_row.get('device_type') or '',
                }

        hosts = {}
        tactic_seen = set()

        for idx, alert in enumerate(alerts):
            host_ip = alert.get('ip') or '(no host)'
            mitre = alert.get('mitre_attack') or {}
            tactic_id = mitre.get('tactic_id') or 'OTHER'
            if tactic_id not in TACTIC_LABELS:
                tactic_id = 'OTHER'
            tactic_seen.add(tactic_id)

            host = hosts.get(host_ip)
            if host is None:
                meta = ip_meta.get(host_ip, {})
                host = {
                    'ip': host_ip,
                    'name': meta.get('name', ''),
                    'group': meta.get('group', ''),
                    'is_local': meta.get('is_local', False),
                    'device_type': meta.get('device_type', ''),
                    'tactics': {},
                    'alert_count': 0,
                    'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'severity_max_rank': 0,
                    'severity_max': '',
                    'first_ts': None,
                    'last_ts': None,
                }
                hosts[host_ip] = host

            severity = (alert.get('severity') or '').lower()
            rank = SEV_RANK.get(severity, 0)
            if rank > host['severity_max_rank']:
                host['severity_max_rank'] = rank
                host['severity_max'] = severity
            if severity in host['severity_counts']:
                host['severity_counts'][severity] += 1

            ts = alert.get('timestamp') or ''
            if ts:
                if host['first_ts'] is None or ts < host['first_ts']:
                    host['first_ts'] = ts
                if host['last_ts'] is None or ts > host['last_ts']:
                    host['last_ts'] = ts

            event = {
                'idx': idx,
                'id': alert.get('id'),
                'title': alert.get('title') or '',
                'severity': severity,
                'category': alert.get('category') or '',
                'timestamp': ts,
                'description': alert.get('description') or '',
                'technique_id': mitre.get('technique_id') or '',
                'technique_name': mitre.get('technique_name') or '',
                'tactic_name': mitre.get('tactic_name') or '',
            }
            host['tactics'].setdefault(tactic_id, []).append(event)
            host['alert_count'] += 1

        # Build the ordered tactic list: kill-chain order first, then 'OTHER'
        # last if used. Only include tactics that actually have data unless the
        # caller asks for the full column set via ?empty=1.
        include_empty = request.args.get('empty', '').strip() in ('1', 'true', 'yes')
        if include_empty:
            ordered = list(TACTIC_ORDER)
            if 'OTHER' in tactic_seen:
                ordered.append('OTHER')
        else:
            ordered = [t for t in TACTIC_ORDER if t in tactic_seen]
            if 'OTHER' in tactic_seen:
                ordered.append('OTHER')

        tactics_info = {t: TACTIC_LABELS[t] for t in ordered}

        # Sort hosts by max severity desc, then alert count desc, then ip asc.
        host_list = sorted(
            hosts.values(),
            key=lambda h: (-h['severity_max_rank'], -h['alert_count'], h['ip']),
        )

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "filename": (scan.get('summary') or {}).get('filename'),
            "analyzed_at": (scan.get('summary') or {}).get('analyzed_at'),
            "tactics_order": ordered,
            "tactics_info": tactics_info,
            "hosts": host_list,
            "host_count": len(host_list),
            "total_alerts": len(alerts),
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return server_error(e)


@scans_bp.route('/api/scans/<int:scan_id>/graph', methods=['GET'])
def graph_view(scan_id):
    """
    Interactive flow graph: nodes = IPs, edges = aggregated peer traffic.

    Top-N IPs by total bytes are returned; edges are kept only when both
    endpoints survive the cut. Edge bytes/packets are divided by 2 because
    the ProtocolStatsAggregator records every packet from both sides of the
    pair, so summing both sides without halving would double-count wire bytes.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
      - in: query
        name: top_n
        schema: {type: integer, default: 200, maximum: 500}
      - in: query
        name: min_bytes
        schema: {type: integer, default: 0}
    responses:
      200: {description: Graph payload}
      404: {description: Scan not found}
    """
    SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    try:
        top_n = int(request.args.get('top_n', 200))
    except (TypeError, ValueError):
        top_n = 200
    top_n = max(10, min(top_n, 500))
    try:
        min_bytes = int(request.args.get('min_bytes', 0))
    except (TypeError, ValueError):
        min_bytes = 0

    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "scan not found"}), 404

        settings = load_settings()
        scan = enrich_results_with_names_and_groups(scan, settings)

        ips = scan.get('ips') or []
        alerts = scan.get('alerts') or []

        # Per-IP severity_max from alerts (graph colours mirror killchain).
        sev_max = {}
        alert_count = {}
        for a in alerts:
            ip = a.get('ip')
            if not ip:
                continue
            alert_count[ip] = alert_count.get(ip, 0) + 1
            r = SEV_RANK.get((a.get('severity') or '').lower(), 0)
            if r > sev_max.get(ip, -1):
                sev_max[ip] = r

        rank_to_sev = {v: k for k, v in SEV_RANK.items()}

        # Rank IPs by total bytes (sent+recv) and keep the top-N.
        ranked = sorted(
            ips,
            key=lambda x: (
                int(x.get('bytes_sent') or 0)
                + int(x.get('bytes_received') or 0)
            ),
            reverse=True,
        )
        kept = []
        for entry in ranked:
            total = (int(entry.get('bytes_sent') or 0)
                     + int(entry.get('bytes_received') or 0))
            if total < min_bytes:
                continue
            kept.append(entry)
            if len(kept) >= top_n:
                break
        kept_ips = {e.get('ip') for e in kept}

        nodes = []
        for entry in kept:
            ip = entry.get('ip')
            rep = entry.get('reputation') or {}
            geo = entry.get('geolocation') or {}
            sev_rank = sev_max.get(ip, -1)
            nodes.append({
                'id': ip,
                'ip': ip,
                'name': entry.get('name') or '',
                'group': entry.get('group') or '',
                'is_local': bool(entry.get('is_local')),
                'device_type': entry.get('device_type') or '',
                'country': geo.get('country') or '',
                'packets_sent': int(entry.get('packets_sent') or 0),
                'packets_received': int(entry.get('packets_received') or 0),
                'bytes_sent': int(entry.get('bytes_sent') or 0),
                'bytes_received': int(entry.get('bytes_received') or 0),
                'bytes_total': (int(entry.get('bytes_sent') or 0)
                                + int(entry.get('bytes_received') or 0)),
                'protocols': entry.get('protocols') or [],
                'alert_count': alert_count.get(ip, int(entry.get('alert_count') or 0)),
                'severity_max': rank_to_sev.get(sev_rank, ''),
                'reputation_score': int(rep.get('reputation_score') or 0),
                'is_malicious': bool(rep.get('is_malicious')),
                'risk_score': int(entry.get('risk_score') or 0),
            })

        # Aggregate edges from results['ip_protocols'] peer breakdown.
        # Each packet is registered on BOTH endpoints, so dividing by 2 at
        # the end recovers wire-level bytes/packets per undirected pair.
        edge_acc = {}
        for ip_proto in (scan.get('ip_protocols') or []):
            src_ip = ip_proto.get('ip')
            if src_ip not in kept_ips:
                continue
            for proto in (ip_proto.get('protocols') or []):
                proto_name = proto.get('name') or ''
                for peer in (proto.get('peers') or []):
                    dst_ip = peer.get('ip')
                    if not dst_ip or dst_ip not in kept_ips or dst_ip == src_ip:
                        continue
                    pair = (src_ip, dst_ip) if src_ip < dst_ip else (dst_ip, src_ip)
                    rec = edge_acc.get(pair)
                    if rec is None:
                        rec = {'bytes': 0, 'packets': 0, 'protocols': {}}
                        edge_acc[pair] = rec
                    rec['bytes'] += int(peer.get('bytes') or 0)
                    rec['packets'] += int(peer.get('packets') or 0)
                    pb = rec['protocols'].get(proto_name)
                    rec['protocols'][proto_name] = (pb or 0) + int(peer.get('bytes') or 0)

        edges = []
        for (a, b), rec in edge_acc.items():
            protos_sorted = sorted(
                rec['protocols'].items(), key=lambda kv: kv[1], reverse=True,
            )
            edges.append({
                'source': a,
                'target': b,
                'bytes': max(rec['bytes'] // 2, 1),
                'packets': max(rec['packets'] // 2, 1),
                'protocols': [p for p, _ in protos_sorted[:8]],
            })
        edges.sort(key=lambda e: e['bytes'], reverse=True)

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "filename": (scan.get('summary') or {}).get('filename'),
            "analyzed_at": (scan.get('summary') or {}).get('analyzed_at'),
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "total_ips": len(ips),
            "truncated": len(ips) > len(nodes),
            "top_n": top_n,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return server_error(e)


@scans_bp.route('/api/scans/<int:scan_id>/mitre-layer', methods=['GET'])
def mitre_navigator_layer(scan_id):
    """
    Export an MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)
    layer JSON for a scan. Each technique observed in alerts becomes a coloured
    cell scored by alert count, with the alert titles aggregated into a tooltip
    comment. Layer schema follows Navigator format v4.5 (compatible with v5).

    ?download=1 sets Content-Disposition so the browser saves the file.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
      - in: query
        name: download
        schema: {type: integer, enum: [0, 1], default: 0}
    responses:
      200: {description: Navigator layer JSON}
      404: {description: Scan not found}
    """
    # MITRE tactic_id (TAxxxx) → Navigator short-name (lowercase-with-dashes).
    # Navigator uses these as the `tactic` field on every technique entry.
    TACTIC_SHORTNAME = {
        'TA0043': 'reconnaissance',
        'TA0042': 'resource-development',
        'TA0001': 'initial-access',
        'TA0002': 'execution',
        'TA0003': 'persistence',
        'TA0004': 'privilege-escalation',
        'TA0005': 'defense-evasion',
        'TA0006': 'credential-access',
        'TA0007': 'discovery',
        'TA0008': 'lateral-movement',
        'TA0009': 'collection',
        'TA0011': 'command-and-control',
        'TA0010': 'exfiltration',
        'TA0040': 'impact',
    }
    SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "scan not found"}), 404

        summary = scan.get('summary') or {}
        alerts = scan.get('alerts') or []

        # Aggregate per (technique_id, tactic_id): count, severity_max, sample titles, IP set.
        agg = {}
        for alert in alerts:
            mitre = alert.get('mitre_attack') or {}
            tid = mitre.get('technique_id') or ''
            tactic_id = mitre.get('tactic_id') or ''
            if not tid or not tactic_id:
                continue
            tactic_short = TACTIC_SHORTNAME.get(tactic_id)
            if not tactic_short:
                continue
            key = (tid, tactic_short)
            rec = agg.get(key)
            if rec is None:
                rec = {
                    'technique_id': tid,
                    'technique_name': mitre.get('technique_name') or '',
                    'tactic': tactic_short,
                    'count': 0,
                    'sev_rank': 0,
                    'titles': {},
                    'ips': set(),
                }
                agg[key] = rec
            rec['count'] += 1
            r = SEV_RANK.get((alert.get('severity') or '').lower(), 0)
            if r > rec['sev_rank']:
                rec['sev_rank'] = r
            title = alert.get('title') or ''
            if title:
                rec['titles'][title] = rec['titles'].get(title, 0) + 1
            ip = alert.get('ip')
            if ip:
                rec['ips'].add(ip)

        max_count = max((rec['count'] for rec in agg.values()), default=0)
        rank_to_sev = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}

        techniques = []
        for rec in agg.values():
            # Top 5 alert titles for the tooltip comment.
            top_titles = sorted(rec['titles'].items(), key=lambda kv: kv[1], reverse=True)[:5]
            comment_lines = [
                f"{rec['technique_name']} ({rec['technique_id']})",
                f"alerts: {rec['count']} | severity_max: {rank_to_sev.get(rec['sev_rank'], 'info')}"
                f" | hosts: {len(rec['ips'])}",
                '',
                'top alert titles:',
            ]
            for t, n in top_titles:
                comment_lines.append(f"  - {t} ×{n}")
            techniques.append({
                'techniqueID': rec['technique_id'],
                'tactic': rec['tactic'],
                'score': rec['count'],
                'color': '',
                'comment': '\n'.join(comment_lines),
                'enabled': True,
                'metadata': [
                    {'name': 'alerts', 'value': str(rec['count'])},
                    {'name': 'severity_max', 'value': rank_to_sev.get(rec['sev_rank'], 'info')},
                    {'name': 'hosts', 'value': str(len(rec['ips']))},
                ],
                'showSubtechniques': '.' in rec['technique_id'],
            })

        # Stable order: by score desc then technique id.
        techniques.sort(key=lambda x: (-x['score'], x['techniqueID']))

        filename = summary.get('filename') or f'scan-{scan_id}'
        analyzed_at = summary.get('analyzed_at') or ''
        layer_name = f"PCAP {filename}"[:120]

        layer = {
            'name': layer_name,
            'versions': {
                'attack': '14',
                'navigator': '4.9.1',
                'layer': '4.5',
            },
            'domain': 'enterprise-attack',
            'description': (
                f"Auto-generated from PCAP analyzer scan #{scan_id} "
                f"({filename}, analyzed_at={analyzed_at}). "
                f"Score = number of alerts mapped to the technique."
            ),
            'filters': {
                'platforms': [
                    'Linux', 'macOS', 'Windows', 'Network', 'Containers',
                    'Office 365', 'SaaS', 'Google Workspace', 'IaaS', 'Azure AD', 'PRE',
                ],
            },
            'sorting': 3,
            'layout': {
                'layout': 'side',
                'aggregateFunction': 'average',
                'showID': False,
                'showName': True,
                'showAggregateScores': False,
                'countUnscored': False,
            },
            'hideDisabled': False,
            'techniques': techniques,
            'gradient': {
                'colors': ['#8ec843ff', '#ffe766ff', '#ff6666ff'],
                'minValue': 1,
                'maxValue': max(max_count, 1),
            },
            'legendItems': [],
            'metadata': [
                {'name': 'scan_id', 'value': str(scan_id)},
                {'name': 'filename', 'value': filename},
                {'name': 'analyzed_at', 'value': analyzed_at},
                {'name': 'total_alerts', 'value': str(len(alerts))},
                {'name': 'techniques_observed', 'value': str(len(techniques))},
            ],
            'links': [],
            'showTacticRowBackground': False,
            'tacticRowBackground': '#dddddd',
            'selectTechniquesAcrossTactics': True,
            'selectSubtechniquesWithParent': False,
        }

        body = json.dumps(layer, indent=2, ensure_ascii=False)
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        if request.args.get('download', '').strip() in ('1', 'true', 'yes'):
            import re as _re
            safe = _re.sub(r'[^A-Za-z0-9._-]', '_', filename)[:120] or f'scan-{scan_id}'
            headers['Content-Disposition'] = (
                f'attachment; filename="{safe}-attack-navigator.json"'
            )
        return Response(body, headers=headers)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return server_error(e)


@scans_bp.route('/api/scans/<int:scan_id>/carved-files', methods=['GET'])
@role_required('viewer')
def list_carved_files(scan_id):
    """
    Return all files carved from HTTP flows for *scan_id*, with hash reputation.
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: scan_id
        schema: {type: integer}
        required: true
    """
    try:
        files = db.get_carved_files_for_scan(scan_id)
        return jsonify({"success": True, "files": files, "count": len(files)})
    except Exception as e:
        return server_error(e)


@scans_bp.route('/api/carved-files/<sha256>/download', methods=['GET'])
@role_required('admin')
def download_carved_file(sha256):
    """
    Stream raw bytes of a carved file. Admin-only (may be live malware).
    ---
    tags: [Scans]
    parameters:
      - in: path
        name: sha256
        schema: {type: string, pattern: '^[0-9a-fA-F]{64}$'}
        required: true
    """
    import re
    if not re.fullmatch(r'[0-9a-fA-F]{64}', sha256 or ''):
        return jsonify({"success": False, "error": "invalid sha256"}), 400
    meta = db.get_carved_file_by_sha256(sha256.lower())
    if not meta:
        return jsonify({"success": False, "error": "not found"}), 404
    on_disk = meta.get('on_disk_path') or ''
    allowed_root = os.path.realpath(
        os.environ.get('CARVED_FILES_DIR')
        or os.path.normpath(os.path.join(
            os.environ.get('UPLOAD_FOLDER', 'data/uploads'),
            '..', 'artifacts',
        ))
    )
    try:
        real = os.path.realpath(on_disk)
        if not real.startswith(allowed_root + os.sep) and real != allowed_root:
            return jsonify({"success": False, "error": "path outside artifacts root"}), 403
        if not os.path.isfile(real):
            return jsonify({"success": False, "error": "file missing from disk"}), 410
        with open(real, 'rb') as f:
            data = f.read()
    except OSError as e:
        return server_error(e)
    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_',
                       meta.get('filename') or f"{sha256}.bin")[:200]
    audit_event(action='download_carved_file', target_type='carved_file',
                target_id=sha256)
    return Response(
        data,
        mimetype='application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename="{safe_name}"',
            'X-Carved-Malicious': '1' if meta.get('malicious') else '0',
        },
    )
