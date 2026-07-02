"""Upload path claiming (collision-safe storage names).

Regression (2026-07): uploads were saved under their sanitized original name
with a plain overwrite, so re-uploading ``capture.pcap`` silently replaced the
file older scans still reference for packet viewer / replay / diff.
``claim_unique_upload_path`` must never clobber and must keep the extension so
``allowed_file`` still accepts the stored name.
"""

import os

from upload_utils import claim_unique_upload_path


def test_first_claim_keeps_original_name(tmp_path):
    path, name = claim_unique_upload_path(str(tmp_path), "capture.pcap")
    assert name == "capture.pcap"
    assert os.path.isfile(path)
    assert os.path.dirname(path) == str(tmp_path)


def test_collision_appends_numeric_suffix_before_extension(tmp_path):
    p1, n1 = claim_unique_upload_path(str(tmp_path), "capture.pcap")
    p2, n2 = claim_unique_upload_path(str(tmp_path), "capture.pcap")
    p3, n3 = claim_unique_upload_path(str(tmp_path), "capture.pcap")
    assert (n1, n2, n3) == ("capture.pcap", "capture-2.pcap", "capture-3.pcap")
    assert len({p1, p2, p3}) == 3
    assert all(os.path.isfile(p) for p in (p1, p2, p3))


def test_existing_file_is_never_overwritten(tmp_path):
    original = tmp_path / "capture.pcap"
    original.write_bytes(b"old scan bytes")
    path, name = claim_unique_upload_path(str(tmp_path), "capture.pcap")
    assert name == "capture-2.pcap"
    assert original.read_bytes() == b"old scan bytes"
    assert path != str(original)
