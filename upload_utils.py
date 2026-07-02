"""Filesystem helpers for PCAP uploads.

Deliberately import-light (os/uuid only): no Flask, no database — so the unit
tests and any worker code can use these helpers without app context.
"""

import os
import uuid

# After this many "-N" suffix attempts something is pathological (or an
# adversary is racing us); fall back to a random suffix that cannot collide.
_MAX_SUFFIX_ATTEMPTS = 1000


def claim_unique_upload_path(upload_root, filename):
    """Reserve a non-clobbering path for ``filename`` inside ``upload_root``.

    Uploads are stored under their sanitized original name, but a second
    upload with the same name must NOT overwrite the first: older scans locate
    their source PCAP by the stored filename (packet viewer, replay, diff),
    so overwriting would silently rebind them to the new file's bytes — and an
    analysis still streaming the old file could have it swapped mid-read.

    On collision a numeric suffix goes before the extension
    (``capture.pcap`` → ``capture-2.pcap`` → ``capture-3.pcap`` …). Each
    candidate is claimed with O_CREAT|O_EXCL, so two concurrent uploads of the
    same name cannot race into the same path.

    Returns ``(filepath, stored_filename)``; the (empty) file already exists
    on return and the caller overwrites it with the upload content.
    """
    stem, ext = os.path.splitext(filename)
    candidate = filename
    n = 1
    while True:
        path = os.path.join(upload_root, candidate)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            n += 1
            if n > _MAX_SUFFIX_ATTEMPTS:
                candidate = f"{stem}-{uuid.uuid4().hex[:8]}{ext}"
            else:
                candidate = f"{stem}-{n}{ext}"
            continue
        os.close(fd)
        return path, candidate
