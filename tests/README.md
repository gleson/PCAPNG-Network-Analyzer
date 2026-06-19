# Test suite

Automated tests for the PCAP detection engine (`pcap_analyzer`).

The engine is tested in isolation: `PCAPAnalyzer(path, settings).analyze()`
takes a file and returns a `results` dict — no database, Celery, Redis or
Flask. Fixture PCAPs are **built programmatically with scapy** (see
`conftest.py::build_pcap`) instead of being checked in as binary blobs, so each
test reads as a spec for the traffic it exercises and stays diffable.

## Layout

| File | Covers |
|------|--------|
| `test_engine_contract.py` | registry sizes (32 streaming / 19 post / 14 aggregators), unique detector names, every detector instantiates, alert-schema invariants, empty + clean-traffic guards |
| `test_kerberos_detector.py` | Kerberoasting (RC4 TGS-REQ) + AES negative |
| `test_smb_pipe_detector.py` | SMB2 named-pipe lateral movement + benign negative + SMB1 `\PIPE\` |
| `test_dcerpc_bind_detector.py` | DCERPC bind to high-risk interfaces (PetitPotam/DCSync) + unknown-UUID negative |
| `test_credential_detectors.py` | SSH brute force + below-threshold negative; cleartext FTP + HTTP Basic auth |
| `test_dns_c2_detectors.py` | DGA domain + pronounceable negative; Cobalt Strike DNS beacon + normal-subdomain negative |
| `test_http_exploit_detector.py` | exploit payloads (Log4Shell/cmd injection on 80/8080) + benign negative |
| `test_scan_detectors.py` | port scan, ping sweep, horizontal scan, SNMP walk, ARP host discovery + a below-threshold negative |
| `test_dns_detectors.py` | DNS tunneling (long high-entropy subdomain) + negatives |
| `test_protocol_detectors.py` | insecure protocols (FTP/Telnet) + HTTPS negative; LLMNR + NBT-NS poisoning + below-threshold negative |
| `test_exfil_beacon_detectors.py` | volume exfiltration, beaconing |
| `test_dns_intel_detectors.py` | fast-flux (many IPs / low TTL), NXDOMAIN spike, suspicious TLD + negatives |
| `test_tunnel_detectors.py` | DoT (known vs unknown resolver), WireGuard / OpenVPN handshakes on non-standard ports, GRE IP-encapsulation + negatives |
| `test_ics_detectors.py` | ICS/OT protocol presence (Modbus/TCP), Modbus write FC from external IP (critical) + internal/read negatives |

## Running locally

```bash
pip install -r requirements-dev.txt
pytest
```

## Running in Docker (canonical environment)

The application image bakes the code in, so mount the suite and run pytest
inside the web container:

```bash
docker compose run --rm \
  -v "$(pwd)/tests:/app/tests" \
  -v "$(pwd)/pytest.ini:/app/pytest.ini" \
  web sh -c "pip install pytest && pytest"
```

## Conventions / gotchas

- **External vs. local IPs**: use the `EXTERNAL_IP` / `LOCAL_IP` constants from
  `conftest.py`. Python 3.12+ classifies the TEST-NET documentation ranges
  (`203.0.113/24`, `198.51.100/24`) as `is_private=True`, so those are *not*
  usable as "external" — the constants use real public IPs (`8.8.8.8`, etc.).
- **Timestamps**: detectors with sliding windows read `pkt.time`. Set it
  explicitly when timing matters; `build_pcap` fills any gaps.
- **No network**: network-backed post-detectors (threat-intel feeds, JA3
  SSLBL, CISA KEV) no-op without `requests` / API keys, so the suite is
  offline.
- **Thresholds**: most fixtures cross the *default* thresholds. Volume exfil's
  10 MB default is lowered via `settings` to avoid building 10 MB of packets —
  this still exercises the byte-accounting and ratio logic.

## Bugs found & fixed while writing this suite

`ModernTunnelStreamingDetector` (WireGuard / OpenVPN / DoQ / GRE-IPIP-SIT
tunnels) was **dead** on every real capture. It read `pkt[IP].proto` and
`bytes(pkt[UDP].payload)`, but the compact `PktView` carried neither: `_IPLayerView`
had no `proto` field and `_UDPLayerView` no payload, so every signature check
silently saw `proto=None` / empty payload. Fix: `pkt_view.py` now exposes
`IP.proto`, and the detector reads the UDP handshake bytes from the already-
extracted `Raw` layer (scapy keeps an unrecognised UDP payload as `Raw`), which
adds no extra memory. Covered by `test_tunnel_detectors.py`.

`LlmnrNbtnsStreamingDetector` was **dead** on every scapy-parsed capture. It
guarded on `if DNS in pkt`, but scapy dissects LLMNR (UDP 5355) as
`LLMNRResponse` and NBT-NS (UDP 137) as `NBNSHeader` — neither is the generic
`DNS` class, and the compact `PktView` didn't extract them at all, so the guard
could never match. Fix: `pkt_view.py` now extracts a normalised qr/ancount view
for both protocols (keyed by the concrete scapy class, re-exported as
`LLMNR_LAYER` / `NBNS_LAYER`), and the detector reads those. Covered by the
LLMNR / NBT-NS tests in `test_protocol_detectors.py`.
