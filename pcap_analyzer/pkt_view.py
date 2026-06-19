"""
PktView — compact packet representation.

scapy.Packet keeps raw buffers and parser state, costing ~2-3 KB per packet.
On 5-10M-packet captures that crosses 30 GB and gets the worker OOM-killed.
PktView extracts only the fields the detectors actually consume into __slots__
objects, cutting per-packet memory ~5-10×.

The interface mimics scapy enough that detection code did not need to change:
    IP in pkt
    pkt[IP].src
    len(pkt)
    pkt.time
    pkt.haslayer(TCP)
"""

from scapy.all import IP, IPv6, TCP, UDP, ARP, DNS, DNSQR, ICMP, Raw, Ether

try:
    from scapy.layers.dhcp import DHCP as _ScapyDHCP
except Exception:
    _ScapyDHCP = None  # type: ignore

# LLMNR (UDP 5355) and NBT-NS (UDP 137) are name-service protocols scapy
# dissects into their OWN classes — NOT the generic DNS class — so detectors
# cannot find them via `DNS in pkt`. We extract a tiny qr/ancount view so the
# LLMNR/NBT-NS poisoning detector can match responses. (haslayer does not
# match the _LLMNR base class, so the concrete LLMNRResponse is bound here.)
try:
    from scapy.layers.llmnr import LLMNRResponse as _ScapyLLMNRResp
except Exception:
    _ScapyLLMNRResp = None  # type: ignore
try:
    from scapy.layers.netbios import NBNSHeader as _ScapyNBNS
except Exception:
    _ScapyNBNS = None  # type: ignore

# Kerberos over TCP/88: scapy dissects the 4-byte RFC4120 length prefix into
# KerberosTCPHeader and (often) the whole ASN.1 message into a Kerberos layer,
# leaving NO Raw layer — or, on a partial parse, a Raw remainder with the
# prefix already stripped. Either way KerberosAbuseStreamingDetector (which
# reads pkt[Raw] and then skips 4 bytes for the prefix) breaks. We re-expose
# the full TCP payload (prefix included) as Raw so its byte-scan works.
try:
    from scapy.layers.kerberos import KerberosTCPHeader as _ScapyKerberosTCP
except Exception:
    _ScapyKerberosTCP = None  # type: ignore

# SMB2/3 named-pipe access: the pipe name (e.g. 'svcctl') travels as the bare
# UTF-16LE filename in an SMB2 CREATE request — the literal "\PIPE\" only
# appears in legacy SMB1. scapy fully parses valid SMB2, so the Raw payload is
# gone and the DCERPC-pipe detector's "\PIPE\" byte-scan never matches modern
# lateral movement (PsExec/Impacket). We extract the parsed CREATE filename.
try:
    from scapy.layers.smb2 import SMB2_Create_Request as _ScapySMB2Create
except Exception:
    _ScapySMB2Create = None  # type: ignore

# DCERPC over ncacn_ip_tcp (TCP/135 + dynamic ports): scapy parses a bind /
# alter-context into DceRpc5Bind/DceRpc5AlterContext, exposing the bound
# interface UUID(s) (abstract syntax). Binding a notorious interface (MS-EFSR
# PetitPotam, MS-RPRN PrinterBug, MS-DRSR DCSync, svcctl, ...) is itself
# actionable, so we collect the UUIDs for the DcerpcBind detector.
try:
    from scapy.layers.dcerpc import (
        DceRpc5Bind as _ScapyDceRpc5Bind,
        DceRpc5AlterContext as _ScapyDceRpc5Alter,
    )
except Exception:
    _ScapyDceRpc5Bind = None  # type: ignore
    _ScapyDceRpc5Alter = None  # type: ignore

try:
    from scapy.layers.inet import IPerror, TCPerror, UDPerror
except Exception:
    IPerror = None  # type: ignore
    TCPerror = None  # type: ignore
    UDPerror = None  # type: ignore


class _IPLayerView:
    __slots__ = ('src', 'dst', 'ttl')


class _TCPLayerView:
    __slots__ = ('sport', 'dport', 'flags')


class _UDPLayerView:
    __slots__ = ('sport', 'dport')


class _ICMPLayerView:
    # inner_* preserve the IP+TCP/UDP header that ICMP error messages
    # (Destination Unreachable type 3, Time Exceeded type 11) embed as
    # evidence of which original packet failed. They let detectors mark
    # the *referenced* flow as "icmp_unreachable" — e.g. an FTP scan that
    # generates only ICMP errors on tcp/21. Set to None when not present.
    __slots__ = (
        'type', 'code',
        'inner_proto', 'inner_ip_src', 'inner_ip_dst',
        'inner_sport', 'inner_dport',
    )


class _ARPLayerView:
    __slots__ = ('op', 'psrc', 'pdst', 'hwsrc', 'hwdst')


class _EtherLayerView:
    __slots__ = ('src', 'dst')


class _DNSAnswerView:
    __slots__ = ('rrname', 'type', 'rdata', 'ttl')


class _DNSLayerView:
    __slots__ = ('qr', 'ancount', 'rcode', 'an')


class _DNSQRLayerView:
    __slots__ = ('qname',)


class _RawLayerView:
    __slots__ = ('load',)

    def __bytes__(self):
        load = self.load
        if isinstance(load, (bytes, bytearray)):
            return bytes(load)
        return b''


class _DHCPLayerView:
    __slots__ = ('options',)


class _NameResponseView:
    """Normalised view of an LLMNR / NBT-NS message: response flag + answers.

    LLMNRResponse exposes ``qr``/``ancount``; NBNSHeader exposes
    ``RESPONSE``/``ANCOUNT``. Both are mapped onto ``qr``/``ancount`` here so
    the detector reads one shape.
    """
    __slots__ = ('qr', 'ancount')


class _Smb2CreateView:
    """The filename requested in an SMB2 CREATE (the named-pipe target)."""
    __slots__ = ('name',)


class _DcerpcBindView:
    """Abstract-syntax interface UUIDs from a DCERPC bind/alter-context."""
    __slots__ = ('uuids',)


class PktView:
    """Visão compacta de um pacote (substitui scapy.Packet em self.packets)."""

    __slots__ = ('time', 'size', '_layers')

    def __init__(self, time=0.0, size=0):
        self.time = time
        self.size = size
        self._layers = {}

    def __contains__(self, layer_cls):
        return layer_cls in self._layers

    def __getitem__(self, layer_cls):
        return self._layers[layer_cls]

    def __len__(self):
        return self.size

    def haslayer(self, layer_cls):
        return layer_cls in self._layers


def extract_pkt_view(pkt):
    """Constrói um PktView extraindo só campos consumidos pelos detectores."""
    try:
        ts = float(pkt.time)
    except Exception:
        ts = 0.0
    try:
        sz = len(pkt)
    except Exception:
        sz = 0
    view = PktView(time=ts, size=sz)

    if Ether in pkt:
        try:
            e = pkt[Ether]
            layer = _EtherLayerView()
            layer.src = e.src
            layer.dst = e.dst
            view._layers[Ether] = layer
        except Exception:
            pass

    if IP in pkt:
        try:
            ip = pkt[IP]
            layer = _IPLayerView()
            layer.src = ip.src
            layer.dst = ip.dst
            layer.ttl = int(ip.ttl) if ip.ttl is not None else 64
            view._layers[IP] = layer
        except Exception:
            pass
    elif IPv6 in pkt:
        try:
            v6 = pkt[IPv6]
            layer = _IPLayerView()
            layer.src = str(v6.src)
            layer.dst = str(v6.dst)
            layer.ttl = int(getattr(v6, 'hlim', 64) or 64)
            view._layers[IPv6] = layer
        except Exception:
            pass

    if TCP in pkt:
        try:
            t = pkt[TCP]
            layer = _TCPLayerView()
            layer.sport = int(t.sport)
            layer.dport = int(t.dport)
            layer.flags = int(t.flags) if t.flags is not None else 0
            view._layers[TCP] = layer
        except Exception:
            pass

    if UDP in pkt:
        try:
            u = pkt[UDP]
            layer = _UDPLayerView()
            layer.sport = int(u.sport)
            layer.dport = int(u.dport)
            view._layers[UDP] = layer
        except Exception:
            pass

    if ICMP in pkt:
        try:
            ic = pkt[ICMP]
            layer = _ICMPLayerView()
            layer.type = int(ic.type) if ic.type is not None else 0
            layer.code = int(ic.code) if getattr(ic, 'code', None) is not None else 0
            layer.inner_proto = None
            layer.inner_ip_src = None
            layer.inner_ip_dst = None
            layer.inner_sport = None
            layer.inner_dport = None
            # ICMP error messages (type 3 unreachable, type 11 ttl-exceeded)
            # embed the original IP+TCP/UDP header. Extract once so detectors
            # can mark the referenced flow.
            if layer.type in (3, 11) and IPerror is not None:
                try:
                    if IPerror in pkt:
                        iperr = pkt[IPerror]
                        layer.inner_ip_src = iperr.src
                        layer.inner_ip_dst = iperr.dst
                        if TCPerror is not None and TCPerror in pkt:
                            tcperr = pkt[TCPerror]
                            layer.inner_proto = 'tcp'
                            layer.inner_sport = int(tcperr.sport)
                            layer.inner_dport = int(tcperr.dport)
                        elif UDPerror is not None and UDPerror in pkt:
                            udperr = pkt[UDPerror]
                            layer.inner_proto = 'udp'
                            layer.inner_sport = int(udperr.sport)
                            layer.inner_dport = int(udperr.dport)
                except Exception:
                    pass
            view._layers[ICMP] = layer
        except Exception:
            pass

    if ARP in pkt:
        try:
            a = pkt[ARP]
            layer = _ARPLayerView()
            layer.op = int(a.op) if a.op is not None else 0
            layer.psrc = a.psrc
            layer.pdst = a.pdst
            layer.hwsrc = a.hwsrc
            layer.hwdst = a.hwdst
            view._layers[ARP] = layer
        except Exception:
            pass

    if DNS in pkt:
        try:
            d = pkt[DNS]
            layer = _DNSLayerView()
            layer.qr = int(d.qr) if d.qr is not None else 0
            layer.ancount = int(d.ancount) if d.ancount is not None else 0
            layer.rcode = int(d.rcode) if d.rcode is not None else 0
            answers = None
            if layer.ancount > 0 and d.an is not None:
                answers = []
                for i in range(layer.ancount):
                    try:
                        rr = d.an[i]
                        item = _DNSAnswerView()
                        item.rrname = rr.rrname
                        item.type = int(rr.type) if getattr(rr, 'type', None) is not None else 0
                        item.rdata = getattr(rr, 'rdata', None)
                        item.ttl = int(rr.ttl) if getattr(rr, 'ttl', None) is not None else 0
                        answers.append(item)
                    except Exception:
                        pass
            layer.an = answers
            view._layers[DNS] = layer
        except Exception:
            pass

    if DNSQR in pkt:
        try:
            q = pkt[DNSQR]
            layer = _DNSQRLayerView()
            layer.qname = q.qname
            view._layers[DNSQR] = layer
        except Exception:
            pass

    if Raw in pkt:
        try:
            r = pkt[Raw]
            layer = _RawLayerView()
            load = r.load
            layer.load = bytes(load) if load else b''
            view._layers[Raw] = layer
        except Exception:
            pass

    # Kerberos/TCP override: re-expose the FULL TCP payload (length prefix
    # included) as Raw so KerberosAbuseStreamingDetector's byte-scan aligns.
    # This intentionally replaces any partial Raw set above.
    if (_ScapyKerberosTCP is not None and TCP in pkt
            and _ScapyKerberosTCP in pkt):
        try:
            full = bytes(pkt[TCP].payload)
            if full:
                layer = _RawLayerView()
                layer.load = full
                view._layers[Raw] = layer
        except Exception:
            pass

    if _ScapyLLMNRResp is not None and _ScapyLLMNRResp in pkt:
        try:
            llmnr = pkt[_ScapyLLMNRResp]
            layer = _NameResponseView()
            layer.qr = int(llmnr.qr) if llmnr.qr is not None else 0
            layer.ancount = int(llmnr.ancount) if llmnr.ancount is not None else 0
            view._layers[_ScapyLLMNRResp] = layer
        except Exception:
            pass

    if _ScapyNBNS is not None and _ScapyNBNS in pkt:
        try:
            nb = pkt[_ScapyNBNS]
            layer = _NameResponseView()
            layer.qr = int(nb.RESPONSE) if nb.RESPONSE is not None else 0
            layer.ancount = int(nb.ANCOUNT) if nb.ANCOUNT is not None else 0
            view._layers[_ScapyNBNS] = layer
        except Exception:
            pass

    if _ScapySMB2Create is not None and _ScapySMB2Create in pkt:
        try:
            nm = pkt[_ScapySMB2Create].Name
            if isinstance(nm, bytes):
                nm = nm.decode('utf-16-le', errors='ignore')
            layer = _Smb2CreateView()
            layer.name = nm or ''
            view._layers[_ScapySMB2Create] = layer
        except Exception:
            pass

    if (_ScapyDceRpc5Bind is not None
            and (_ScapyDceRpc5Bind in pkt or _ScapyDceRpc5Alter in pkt)):
        try:
            uuids = []
            for cls in (_ScapyDceRpc5Bind, _ScapyDceRpc5Alter):
                if cls is None or cls not in pkt:
                    continue
                for ctx in (pkt[cls].context_elem or []):
                    try:
                        u = ctx.abstract_syntax.if_uuid
                        if u is not None:
                            uuids.append(str(u).lower())
                    except Exception:
                        continue
            if uuids:
                layer = _DcerpcBindView()
                layer.uuids = uuids
                view._layers[_ScapyDceRpc5Bind] = layer
        except Exception:
            pass

    if _ScapyDHCP is not None and _ScapyDHCP in pkt:
        try:
            opts = pkt[_ScapyDHCP].options
            keep = []
            if opts:
                for opt in opts:
                    if not isinstance(opt, tuple) or len(opt) < 2:
                        continue
                    name = opt[0]
                    if name in ('vendor_class_id', 'hostname', 'param_req_list'):
                        keep.append(opt)
            layer = _DHCPLayerView()
            layer.options = keep
            view._layers[_ScapyDHCP] = layer
        except Exception:
            pass

    return view


# Layer keys re-exported so detectors index the view with the same class
# objects used to store the layers above.
LLMNR_LAYER = _ScapyLLMNRResp
NBNS_LAYER = _ScapyNBNS
SMB2_CREATE_LAYER = _ScapySMB2Create
DCERPC_BIND_LAYER = _ScapyDceRpc5Bind


__all__ = [
    "PktView",
    "extract_pkt_view",
    "LLMNR_LAYER",
    "NBNS_LAYER",
    "SMB2_CREATE_LAYER",
    "DCERPC_BIND_LAYER",
    "_NameResponseView",
    "_Smb2CreateView",
    "_DcerpcBindView",
    "_IPLayerView",
    "_TCPLayerView",
    "_UDPLayerView",
    "_ICMPLayerView",
    "_ARPLayerView",
    "_EtherLayerView",
    "_DNSAnswerView",
    "_DNSLayerView",
    "_DNSQRLayerView",
    "_RawLayerView",
    "_DHCPLayerView",
]
