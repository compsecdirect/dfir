#!/usr/bin/env python3
"""pcap-to-drawio-multipage-fixed.py (Python 3.12)

Convert a PCAP/PCAPNG capture into an interactive **multi-page** draw.io / diagrams.net
network map.

This script is based on the earlier pcap-to-drawio version that produced the desired
host label format (hostname/IP/MAC + inferred open ports) and tooltip behavior.
It also incorporates the requested new functionality:

- **Overview page** (main page): shows only the **Top N (default 200)** hosts by total
  traffic (TX+RX), ordered from greatest to least. Each host is clickable and links to
  that host's detail page.
- **Per-host detail page**: one page per observed host. Each page contains the focal host
  and every peer that communicated with it, with **arrowed edges** to show direction of
  traffic and **edge tooltips** describing the communications observed.
- **Remainder page** (last page, only if hosts > Top N): shows all hosts beyond the Top N
  in a single grid view, with each host linking to its own detail page.

Fixes included (from earlier feedback):
- Hosts are created **ONLY** from observed IPv4/IPv6 src/dst addresses (NOT from DNS-only answers).
- Improved spacing/layout (avoids label overlap by using larger node geometry + smaller fonts).
- Tooltips include inferred hosted services ("open ports" as observed in the capture).
- No unreachable code after returns; reduced unused imports.
- Error handling is explicit: packet decode errors raise with packet index context.

Dependencies:
  pip install dpkt

Usage:
  python3 pcap-to-drawio.py input.pcapng output.drawio

"""

from __future__ import annotations

import argparse
import io
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import datetime as _dt
import html
import ipaddress
import math
import re
import socket
import struct
import sys
import uuid
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    import dpkt  # type: ignore
except Exception as e:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: dpkt\n\nInstall with:\n  pip install dpkt\n"
    ) from e


# ---------------------------------------------------------------------------
# Branding/logo
# ---------------------------------------------------------------------------

BRANDING_TEXT = "Network Maps: pcap to draw.io by CompSec Direct® CompSecDirect.com"

LOGO_PNG_B64 = (
    "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"
)
LOGO_DATA_URI = "data:image/png," + LOGO_PNG_B64


def branding_html(text: str) -> str:
    # Heading 3-ish, green text, black background
    safe_text = html.escape(text)
    return (
        '<div style="text-align:left;">'
        '<span style="display:inline-block;'
        "background:#000000;"
        "color:#0197FF;"
        "padding:0px 0px;"
        "border-radius:6px;"
        "font-size:10px;"
        "font-weight:600;"
        "line-height:1.2;"
        '">'
        f"{safe_text}"
        "</span></div>"
    )


def branding_style() -> str:
    return (
        f"shape=image;image={LOGO_DATA_URI};aspect=fixed;imageAspect=0;"
        "html=1;whiteSpace=wrap;"
        "labelPosition=right;verticalLabelPosition=middle;"
        "align=left;verticalAlign=middle;"
        "spacingLeft=0;"
        "strokeColor=none;fillColor=none;"
    )


def html_label_with_tooltip(label_text: str, tooltip_text: str) -> str:
    """HTML label with tooltip stored in the title attribute."""
    safe_label = html.escape(label_text).replace("\n", "<br/>")
    safe_tip = html.escape(tooltip_text).replace("\n", "&#10;")

    # Smaller font and slightly larger padding than the previous version to reduce overlap.
    return (
        f'<div title="{safe_tip}" style="text-align:center;">'
        f'<span style="display:inline-block;'
        f'background:#0b0f10;'
        f'border:1px solid #22c55e;'
        f'color:#00ff7f;'
        f'padding:4px 10px;'
        f'border-radius:8px;'
        f'font-size:12px;'
        f'font-weight:600;'
        f'line-height:1.25;'
        f'font-family:Consolas, Menlo, monospace;">{safe_label}</span>'
        f"</div>"
    )


def html_edge_label_with_tooltip(label_text: str, tooltip_text: str) -> str:
    safe_label = html.escape(label_text).replace("\n", "<br/>")
    safe_tip = html.escape(tooltip_text).replace("\n", "&#10;")
    return (
        f'<div title="{safe_tip}" style="text-align:center;">'
        f'<span style="display:inline-block;'
        f'background:#ffffffcc;'
        f'border:1px solid #5f6368;'
        f'color:#202124;'
        f'padding:2px 6px;'
        f'border-radius:6px;'
        f'font-size:10px;'
        f'font-weight:600;'
        f'line-height:1.2;'
        f'font-family:Consolas, Menlo, monospace;">{safe_label}</span>'
        f"</div>"
    )


# ---------------------------------------------------------------------------
# Capture analysis data model
# ---------------------------------------------------------------------------

KNOWN_TCP_SERVER_PORTS: Set[int] = {
    20,
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    123,
    135,
    139,
    143,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    5985,
    5986,
    6379,
    8080,
    8443,
}

KNOWN_UDP_SERVER_PORTS: Set[int] = {
    53,
    67,
    68,
    69,
    123,
    137,
    138,
    161,
    162,
    500,
    514,
    520,
    546,
    547,
    631,
    1900,
    4500,
    5353,
    5355,
}


def _human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    f = float(n)
    for u in units:
        if f < 1024.0 or u == units[-1]:
            return f"{f:.1f}{u}" if u != "B" else f"{int(f)}B"
        f /= 1024.0
    return f"{int(n)}B"


def _safe_ip(ip_text: str) -> str:
    return str(ipaddress.ip_address(ip_text))


def _port_key(port: int, proto: str) -> str:
    return f"{int(port)}/{proto}"


@dataclass
class HostStats:
    ip: str
    macs: Counter[str] = field(default_factory=Counter)
    hostnames: Set[str] = field(default_factory=set)
    tx_bytes: int = 0
    rx_bytes: int = 0
    peers_tx: Counter[str] = field(default_factory=Counter)  # dst_ip -> bytes
    peers_rx: Counter[str] = field(default_factory=Counter)  # src_ip -> bytes
    server_ports: Counter[str] = field(default_factory=Counter)
    client_ports: Counter[str] = field(default_factory=Counter)

    def best_mac(self) -> Optional[str]:
        if not self.macs:
            return None
        return self.macs.most_common(1)[0][0]

    def best_name(self) -> Optional[str]:
        if not self.hostnames:
            return None
        # prefer shortest, then lexicographic
        return sorted(self.hostnames, key=lambda s: (len(s), s))[0]


@dataclass
class CommDirStats:
    bytes: int = 0
    packets: int = 0
    tcp_dports: Counter[int] = field(default_factory=Counter)
    udp_dports: Counter[int] = field(default_factory=Counter)
    other_protos: Counter[int] = field(default_factory=Counter)


# ---------------------------------------------------------------------------
# PCAP/PCAPNG parsing helpers
# ---------------------------------------------------------------------------

class _PrependStream(io.RawIOBase):
    def __init__(self, first_bytes: bytes, fh: io.BufferedReader):
        super().__init__()
        self._buf = io.BytesIO(first_bytes)
        self._fh = fh

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        b = self._buf.read(size)
        if size != -1 and len(b) >= size:
            return b
        rest = self._fh.read(-1 if size == -1 else size - len(b))
        return b + rest


def _iter_packets(path: str) -> Iterable[Tuple[float, bytes, Optional[int]]]:
    """Yield (ts, buf, linktype) for pcap or pcapng."""
    with open(path, "rb") as fh:
        first = fh.read(4)
        if len(first) < 4:
            raise RuntimeError("Capture is empty or too small")

        # pcap magic
        if first in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            fh.seek(0)
            reader = dpkt.pcap.Reader(fh)
            linktype = getattr(reader, "datalink", lambda: None)()
            for ts, buf in reader:
                yield ts, buf, linktype
            return

        # pcapng magic 0x0A0D0D0A
        if first == b"\x0a\x0d\x0d\x0a":
            fh.seek(0)
            reader = dpkt.pcapng.Reader(fh)
            for ts, buf in reader:
                # dpkt pcapng can contain multiple interfaces; linktype may vary
                lt = getattr(reader, "datalink", None)
                linktype = lt() if callable(lt) else None
                yield ts, buf, linktype
            return

        # Unknown: attempt pcap, then pcapng
        fh.seek(0)
        data = fh.read()
        bio = io.BytesIO(data)
        try:
            reader = dpkt.pcap.Reader(bio)
            linktype = getattr(reader, "datalink", lambda: None)()
            for ts, buf in reader:
                yield ts, buf, linktype
            return
        except Exception:
            bio.seek(0)
            try:
                reader = dpkt.pcapng.Reader(bio)
                for ts, buf in reader:
                    lt = getattr(reader, "datalink", None)
                    linktype = lt() if callable(lt) else None
                    yield ts, buf, linktype
                return
            except Exception as e:
                raise RuntimeError(f"Unrecognized capture format: {e}") from e


def _try_parse_l3(buf: bytes, linktype: Optional[int]) -> Tuple[Optional[object], Optional[bytes], Optional[bytes]]:
    """Try to extract L3 packet and L2 src/dst MAC bytes.

    Returns (l3, src_mac_bytes, dst_mac_bytes).
    l3 is dpkt.ip.IP or dpkt.ip6.IP6 when successful.
    """

    # Common link types: Ethernet (1), Linux cooked (113), Raw IP (101), NULL/Loopback (0)
    lt = linktype

    # Ethernet (default)
    if lt is None or lt == dpkt.pcap.DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        return eth.data, getattr(eth, "src", None), getattr(eth, "dst", None)

    if lt == dpkt.pcap.DLT_LINUX_SLL:
        sll = dpkt.sll.SLL(buf)
        # dpkt.sll.SLL has src bytes in sll.addr
        src = getattr(sll, "addr", None)
        return sll.data, src, None

    if lt == dpkt.pcap.DLT_RAW:
        # buf is already IP
        try:
            ip = dpkt.ip.IP(buf)
            return ip, None, None
        except Exception:
            try:
                ip6 = dpkt.ip6.IP6(buf)
                return ip6, None, None
            except Exception:
                return None, None, None

    if lt == dpkt.pcap.DLT_NULL:
        # 4-byte family header, network byte order varies by OS; dpkt docs suggest host order
        if len(buf) < 4:
            return None, None, None
        family = struct.unpack("I", buf[:4])[0]
        payload = buf[4:]
        if family == socket.AF_INET:
            return dpkt.ip.IP(payload), None, None
        if family == socket.AF_INET6:
            return dpkt.ip6.IP6(payload), None, None
        return None, None, None

    # Unknown linktype
    return None, None, None


def _ip_text(ip_pkt: object) -> Tuple[str, str, int, bytes]:
    """Return (src_ip, dst_ip, proto, payload_bytes)."""
    if isinstance(ip_pkt, dpkt.ip.IP):
        src = socket.inet_ntop(socket.AF_INET, ip_pkt.src)
        dst = socket.inet_ntop(socket.AF_INET, ip_pkt.dst)
        proto = int(ip_pkt.p)
        return _safe_ip(src), _safe_ip(dst), proto, bytes(ip_pkt.data) if ip_pkt.data else b""
    if isinstance(ip_pkt, dpkt.ip6.IP6):
        src = socket.inet_ntop(socket.AF_INET6, ip_pkt.src)
        dst = socket.inet_ntop(socket.AF_INET6, ip_pkt.dst)
        proto = int(ip_pkt.nxt)
        return _safe_ip(src), _safe_ip(dst), proto, bytes(ip_pkt.data) if ip_pkt.data else b""
    raise TypeError("Not an IPv4/IPv6 packet")


def _ip_wire_len(ip_pkt: object, fallback_len: int) -> int:
    if isinstance(ip_pkt, dpkt.ip.IP):
        try:
            return int(ip_pkt.len)
        except Exception:
            return fallback_len
    if isinstance(ip_pkt, dpkt.ip6.IP6):
        try:
            return 40 + int(ip_pkt.plen)
        except Exception:
            return fallback_len
    return fallback_len


# ---------------------------------------------------------------------------
# HTTP/TLS hostname extraction (best-effort)
# ---------------------------------------------------------------------------

_HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"CONNECT ",
    b"PATCH ",
)


def _extract_http_host(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    if not payload.startswith(_HTTP_METHODS):
        return None
    try:
        head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="ignore")
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip().lower()
                return host or None
    except Exception:
        return None
    return None


def _extract_tls_sni(payload: bytes) -> Optional[str]:
    # Minimal TLS ClientHello SNI parser
    if not payload or len(payload) < 5:
        return None
    if payload[0] != 0x16 or payload[1] != 0x03:
        return None
    try:
        rec_len = struct.unpack("!H", payload[3:5])[0]
        body = payload[5 : 5 + rec_len]
        if len(body) < 4 or body[0] != 0x01:
            return None
        hs_len = int.from_bytes(body[1:4], "big")
        hs = body[4 : 4 + hs_len]
        if len(hs) < 34:
            return None
        idx = 34
        sid_len = hs[idx]
        idx += 1 + sid_len
        cs_len = struct.unpack("!H", hs[idx : idx + 2])[0]
        idx += 2 + cs_len
        comp_len = hs[idx]
        idx += 1 + comp_len
        ext_len = struct.unpack("!H", hs[idx : idx + 2])[0]
        idx += 2
        exts = hs[idx : idx + ext_len]

        j = 0
        while j + 4 <= len(exts):
            etype = struct.unpack("!H", exts[j : j + 2])[0]
            elen = struct.unpack("!H", exts[j + 2 : j + 4])[0]
            j += 4
            edata = exts[j : j + elen]
            j += elen
            if etype != 0x0000 or len(edata) < 2:
                continue
            list_len = struct.unpack("!H", edata[0:2])[0]
            k = 2
            while k + 3 <= len(edata) and (k - 2) < list_len:
                name_type = edata[k]
                k += 1
                name_len = struct.unpack("!H", edata[k : k + 2])[0]
                k += 2
                name = edata[k : k + name_len]
                k += name_len
                if name_type == 0 and name:
                    return name.decode("utf-8", errors="ignore").strip().lower() or None
    except (struct.error, IndexError, ValueError):
        return None
    return None


# ---------------------------------------------------------------------------
# DNS parsing (answers only) - no host creation here
# ---------------------------------------------------------------------------


def _parse_dns_answers(dns_payload: bytes) -> List[Tuple[str, str]]:
    """Return list of (ip, name) from DNS answers (A/AAAA/PTR)."""
    out: List[Tuple[str, str]] = []
    try:
        dns = dpkt.dns.DNS(dns_payload)
    except (dpkt.UnpackError, ValueError):
        return out

    for rr in getattr(dns, "an", []) or []:
        try:
            if rr.type == dpkt.dns.DNS_A and isinstance(rr.rdata, (bytes, bytearray)) and len(rr.rdata) == 4:
                ip = socket.inet_ntop(socket.AF_INET, rr.rdata)
                out.append((_safe_ip(ip), rr.name.rstrip(".").lower()))
            elif rr.type == dpkt.dns.DNS_AAAA and isinstance(rr.rdata, (bytes, bytearray)) and len(rr.rdata) == 16:
                ip = socket.inet_ntop(socket.AF_INET6, rr.rdata)
                out.append((_safe_ip(ip), rr.name.rstrip(".").lower()))
            elif rr.type == dpkt.dns.DNS_PTR:
                target = rr.ptrname.rstrip(".").lower() if hasattr(rr, "ptrname") else ""
                if not target:
                    continue
                rev_name = rr.name.rstrip(".").lower()
                if rev_name.endswith("in-addr.arpa"):
                    parts = rev_name.replace(".in-addr.arpa", "").split(".")
                    parts.reverse()
                    ip = ".".join(parts)
                    try:
                        out.append((_safe_ip(ip), target))
                    except ValueError:
                        pass
                elif rev_name.endswith("ip6.arpa"):
                    nibbles = rev_name.replace(".ip6.arpa", "").split(".")
                    if len(nibbles) == 32:
                        nibbles.reverse()
                        hexs = "".join(nibbles)
                        ip6 = ":".join(hexs[i : i + 4] for i in range(0, 32, 4))
                        try:
                            out.append((str(ipaddress.IPv6Address(ip6)), target))
                        except Exception:
                            pass
        except Exception as e:
            raise RuntimeError(f"DNS parse error: {e}") from e

    return out


# ---------------------------------------------------------------------------
# TCP/UDP flow inference (from original script)
# ---------------------------------------------------------------------------


def _is_ephemeral(port: int, low: int = 49152) -> bool:
    return int(port) >= low


@dataclass
class TcpFlow:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    syn_seen: bool = False
    synack_seen: bool = False
    client_payload_bytes: int = 0
    server_payload_bytes: int = 0


@dataclass
class UdpFlow:
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    a_to_b_pkts: int = 0
    b_to_a_pkts: int = 0
    a_to_b_bytes: int = 0
    b_to_a_bytes: int = 0


def _flow_key_tcp(a_ip: str, a_port: int, b_ip: str, b_port: int) -> Tuple[str, int, str, int]:
    if (a_ip, a_port) <= (b_ip, b_port):
        return a_ip, a_port, b_ip, b_port
    return b_ip, b_port, a_ip, a_port


def _flow_key_udp(a_ip: str, a_port: int, b_ip: str, b_port: int) -> Tuple[str, int, str, int]:
    if (a_ip, a_port) <= (b_ip, b_port):
        return a_ip, a_port, b_ip, b_port
    return b_ip, b_port, a_ip, a_port


def _guess_server_side_tcp(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, int, str, int]:
    # Heuristic: well-known port / non-ephemeral tends to be server.
    # If both are non-ephemeral, prefer known server ports list.
    if dst_port in KNOWN_TCP_SERVER_PORTS and src_port not in KNOWN_TCP_SERVER_PORTS:
        return src_ip, src_port, dst_ip, dst_port
    if src_port in KNOWN_TCP_SERVER_PORTS and dst_port not in KNOWN_TCP_SERVER_PORTS:
        return dst_ip, dst_port, src_ip, src_port

    if _is_ephemeral(src_port) and not _is_ephemeral(dst_port):
        return src_ip, src_port, dst_ip, dst_port
    if _is_ephemeral(dst_port) and not _is_ephemeral(src_port):
        return dst_ip, dst_port, src_ip, src_port

    # fallback: treat destination as server
    return src_ip, src_port, dst_ip, dst_port


def _guess_server_side_udp(a_ip: str, a_port: int, b_ip: str, b_port: int) -> Tuple[str, int, str, int]:
    # Prefer known UDP service ports
    if a_port in KNOWN_UDP_SERVER_PORTS and b_port not in KNOWN_UDP_SERVER_PORTS:
        return b_ip, b_port, a_ip, a_port
    if b_port in KNOWN_UDP_SERVER_PORTS and a_port not in KNOWN_UDP_SERVER_PORTS:
        return a_ip, a_port, b_ip, b_port

    # prefer non-ephemeral
    if _is_ephemeral(a_port) and not _is_ephemeral(b_port):
        return a_ip, a_port, b_ip, b_port
    if _is_ephemeral(b_port) and not _is_ephemeral(a_port):
        return b_ip, b_port, a_ip, a_port

    # fallback: treat the lower port as server
    if a_port <= b_port:
        return b_ip, b_port, a_ip, a_port
    return a_ip, a_port, b_ip, b_port


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_capture(path: str) -> Tuple[Dict[str, HostStats], Dict[Tuple[str, str], CommDirStats]]:
    hosts: Dict[str, HostStats] = {}

    # pending enrichments (do not create hosts from these)
    pending_names_by_ip: Dict[str, Set[str]] = defaultdict(set)
    pending_macs_by_ip: Dict[str, Counter[str]] = defaultdict(Counter)
    mac_to_dhcp_name: Dict[str, str] = {}

    tcp_flows: Dict[Tuple[str, int, str, int], TcpFlow] = {}
    udp_flows: Dict[Tuple[str, int, str, int], UdpFlow] = {}

    dir_comms: Dict[Tuple[str, str], CommDirStats] = {}

    def host(ip: str) -> HostStats:
        ip = _safe_ip(ip)
        if ip not in hosts:
            hs = HostStats(ip=ip)
            # apply pending enrichments
            if ip in pending_names_by_ip:
                hs.hostnames |= pending_names_by_ip.pop(ip)
            if ip in pending_macs_by_ip:
                hs.macs += pending_macs_by_ip.pop(ip)
            hosts[ip] = hs
        return hosts[ip]

    def comm(src: str, dst: str) -> CommDirStats:
        key = (src, dst)
        if key not in dir_comms:
            dir_comms[key] = CommDirStats()
        return dir_comms[key]

    pkt_i = 0
    for ts, buf, linktype in _iter_packets(path):
        pkt_i += 1
        try:
            l3, src_mac_b, dst_mac_b = _try_parse_l3(buf, linktype)
        except Exception as e:
            raise RuntimeError(f"Packet {pkt_i}: L2/L3 decode failed: {e}") from e

        # ARP: capture MAC/IP mapping but do NOT create hosts
        if isinstance(l3, dpkt.arp.ARP):
            try:
                spa = socket.inet_ntop(socket.AF_INET, l3.spa)
                tpa = socket.inet_ntop(socket.AF_INET, l3.tpa)
                sha = ":".join(f"{b:02x}" for b in l3.sha) if getattr(l3, "sha", None) else ""
                tha = ":".join(f"{b:02x}" for b in l3.tha) if getattr(l3, "tha", None) else ""
                if sha:
                    pending_macs_by_ip[_safe_ip(spa)][sha] += 1
                    if _safe_ip(spa) in hosts:
                        hosts[_safe_ip(spa)].macs[sha] += 1
                if tha:
                    pending_macs_by_ip[_safe_ip(tpa)][tha] += 1
                    if _safe_ip(tpa) in hosts:
                        hosts[_safe_ip(tpa)].macs[tha] += 1
            except Exception as e:
                raise RuntimeError(f"Packet {pkt_i}: ARP parse failed: {e}") from e
            continue

        # Only IPv4/IPv6 are hosts
        if not isinstance(l3, (dpkt.ip.IP, dpkt.ip6.IP6)):
            continue

        try:
            src_ip, dst_ip, proto, l4_payload = _ip_text(l3)
        except Exception as e:
            raise RuntimeError(f"Packet {pkt_i}: IP decode failed: {e}") from e

        wire_len = _ip_wire_len(l3, fallback_len=len(buf))

        # Host creation based ONLY on observed IP src/dst
        hs_src = host(src_ip)
        hs_dst = host(dst_ip)

        # MAC enrichment (best-effort)
        if src_mac_b and len(src_mac_b) >= 6:
            hs_src.macs[":".join(f"{b:02x}" for b in src_mac_b[:6])] += 1
        if dst_mac_b and len(dst_mac_b) >= 6:
            hs_dst.macs[":".join(f"{b:02x}" for b in dst_mac_b[:6])] += 1

        hs_src.tx_bytes += wire_len
        hs_dst.rx_bytes += wire_len
        hs_src.peers_tx[dst_ip] += wire_len
        hs_dst.peers_rx[src_ip] += wire_len

        # Directional comm stats
        cs = comm(src_ip, dst_ip)
        cs.bytes += wire_len
        cs.packets += 1

        # Transport parsing
        if proto == dpkt.ip.IP_PROTO_TCP:
            try:
                tcp = dpkt.tcp.TCP(l4_payload)
            except Exception:
                # dpkt already parsed ip.data in many cases; fall back
                tcp = l3.data if isinstance(getattr(l3, "data", None), dpkt.tcp.TCP) else None
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            sport = int(tcp.sport)
            dport = int(tcp.dport)
            cs.tcp_dports[dport] += 1

            flags = int(tcp.flags)
            syn = bool(flags & dpkt.tcp.TH_SYN)
            ack = bool(flags & dpkt.tcp.TH_ACK)

            # Track TCP flows
            a_ip, a_port, b_ip, b_port = src_ip, sport, dst_ip, dport
            key = _flow_key_tcp(a_ip, a_port, b_ip, b_port)
            if key not in tcp_flows:
                client_ip, client_port, server_ip, server_port = _guess_server_side_tcp(a_ip, a_port, b_ip, b_port)
                tcp_flows[key] = TcpFlow(client_ip, client_port, server_ip, server_port)
            flow = tcp_flows[key]

            payload = bytes(tcp.data) if tcp.data else b""

            # SYN seen: client attempted
            if syn and not ack:
                flow.syn_seen = True
                hs_src.client_ports[_port_key(flow.server_port, "tcp")] += 1

            # SYN-ACK seen
            if syn and ack:
                flow.synack_seen = True

            # Payload direction inference (rough)
            if payload:
                if src_ip == flow.server_ip and sport == flow.server_port:
                    flow.server_payload_bytes += len(payload)
                else:
                    flow.client_payload_bytes += len(payload)

                # Best-effort hostname extraction
                http_host = _extract_http_host(payload)
                if http_host:
                    # host header belongs to destination endpoint
                    pending_names_by_ip[dst_ip].add(http_host)
                    if dst_ip in hosts:
                        hosts[dst_ip].hostnames.add(http_host)

                sni = _extract_tls_sni(payload)
                if sni:
                    pending_names_by_ip[dst_ip].add(sni)
                    if dst_ip in hosts:
                        hosts[dst_ip].hostnames.add(sni)

        elif proto == dpkt.ip.IP_PROTO_UDP:
            try:
                udp = dpkt.udp.UDP(l4_payload)
            except Exception:
                udp = l3.data if isinstance(getattr(l3, "data", None), dpkt.udp.UDP) else None
            if not isinstance(udp, dpkt.udp.UDP):
                continue

            sport = int(udp.sport)
            dport = int(udp.dport)
            cs.udp_dports[dport] += 1
            payload = bytes(udp.data) if udp.data else b""

            # DNS enrichment
            if sport == 53 or dport == 53:
                for ip_ans, name in _parse_dns_answers(payload):
                    pending_names_by_ip[ip_ans].add(name)
                    if ip_ans in hosts:
                        hosts[ip_ans].hostnames.add(name)

            # DHCP hostname option 12
            if (sport, dport) in [(67, 68), (68, 67)] and payload:
                try:
                    dhcp = dpkt.dhcp.DHCP(payload)
                    chaddr = getattr(dhcp, "chaddr", b"")
                    mac = ":".join(f"{b:02x}" for b in chaddr[:6]) if chaddr else ""
                    hostname = None
                    for opt_type, opt_val in getattr(dhcp, "opts", []) or []:
                        if opt_type == 12 and opt_val:
                            hostname = opt_val.decode("utf-8", errors="ignore").strip().lower() or None
                            break
                    if mac and hostname:
                        mac_to_dhcp_name[mac] = hostname
                except (dpkt.UnpackError, ValueError):
                    pass

            # Track UDP flows for server inference
            a_ip, a_port, b_ip, b_port = src_ip, sport, dst_ip, dport
            key = _flow_key_udp(a_ip, a_port, b_ip, b_port)
            if key not in udp_flows:
                udp_flows[key] = UdpFlow(a_ip, a_port, b_ip, b_port)
            flow = udp_flows[key]
            if src_ip == flow.a_ip and sport == flow.a_port:
                flow.a_to_b_pkts += 1
                flow.a_to_b_bytes += len(payload)
            else:
                flow.b_to_a_pkts += 1
                flow.b_to_a_bytes += len(payload)

            # sender attempted (client-ish)
            hs_src.client_ports[_port_key(dport, "udp")] += 1

        else:
            cs.other_protos[proto] += 1

    # Apply DHCP name mapping to observed hosts
    for ip_str, hs in hosts.items():
        mac = hs.best_mac()
        if mac and mac in mac_to_dhcp_name:
            hs.hostnames.add(mac_to_dhcp_name[mac])

    # Finalize TCP inferred server ports
    for flow in tcp_flows.values():
        server_is_active = flow.synack_seen or flow.server_payload_bytes > 0
        if server_is_active:
            hosts[flow.server_ip].server_ports[_port_key(flow.server_port, "tcp")] += 1
        # mid-stream client inference
        if (not flow.syn_seen) and (flow.client_payload_bytes > 0 or flow.server_payload_bytes > 0):
            hosts[flow.client_ip].client_ports[_port_key(flow.server_port, "tcp")] += 1

    # Finalize UDP inferred server ports
    for flow in udp_flows.values():
        client_ip, client_port, server_ip, server_port = _guess_server_side_udp(flow.a_ip, flow.a_port, flow.b_ip, flow.b_port)

        if flow.a_to_b_pkts > 0 and flow.b_to_a_pkts > 0:
            hosts[server_ip].server_ports[_port_key(server_port, "udp")] += 1
            continue

        inbound_pkts = 0
        inbound_bytes = 0
        if server_ip == flow.a_ip and server_port == flow.a_port:
            inbound_pkts = flow.b_to_a_pkts
            inbound_bytes = flow.b_to_a_bytes
        elif server_ip == flow.b_ip and server_port == flow.b_port:
            inbound_pkts = flow.a_to_b_pkts
            inbound_bytes = flow.a_to_b_bytes

        if inbound_pkts <= 0 or inbound_bytes <= 0:
            continue

        if (server_port in KNOWN_UDP_SERVER_PORTS) or (server_port <= 1024) or (inbound_pkts >= 3):
            hosts[server_ip].server_ports[_port_key(server_port, "udp")] += 1

    return hosts, dir_comms


# ---------------------------------------------------------------------------
# Device inference / draw.io generation helpers
# ---------------------------------------------------------------------------

SHAPES = {
    "network": "mxgraph.mscae.enterprise.internet",
    "router": "mxgraph.mscae.enterprise.router",
    "switch": "mxgraph.mscae.enterprise.device",
    "firewall": "mxgraph.cisco_safe.security_icons.firewall",
    "wireless_ap": "mxgraph.ios7.icons.wifi",
    "server": "mxgraph.mscae.enterprise.server_generic",
    "workstation": "mxgraph.mscae.enterprise.workstation_client",
    "printer": "mxgraph.cisco19.printer",
    "ip_phone": "mxgraph.cisco19.ip_phone",
    "camera": "mxgraph.aws4.camera2",
    "unknown": "mxgraph.mscae.enterprise.device",
}


def style_for_device(device_type: str, clickable: bool = True, focal: bool = False) -> str:
    """Return a diagrams.net style string for a host/device node.

    Keeps built-in stencil shapes, but improves scanability with a dark fill and
    device-specific accent strokes.
    """

    shape = SHAPES.get(device_type, SHAPES["unknown"])

    accent_by_type = {
        "network": "#a78bfa",      # purple
        "router": "#38bdf8",       # cyan
        "switch": "#60a5fa",       # blue
        "firewall": "#f97316",     # orange
        "wireless_ap": "#22c55e",  # green
        "server": "#22c55e",       # green
        "workstation": "#14b8a6",  # teal
        "printer": "#fb7185",      # rose
        "ip_phone": "#f59e0b",     # amber
        "camera": "#f43f5e",       # red
        "unknown": "#9ca3af",      # gray
    }

    stroke = "#fbbc04" if focal else accent_by_type.get(device_type, "#22c55e")

    return (
        f"shape={shape};"
        "html=1;whiteSpace=wrap;align=center;verticalAlign=middle;"
        "shadow=1;strokeWidth=2;"
        "fillColor=#111827;"
        f"strokeColor={stroke};"
        "fontFamily=Consolas;fontSize=12;fontColor=#00ff7f;"
        + ("cursor=pointer;" if clickable else "")
    )


def _ports_to_sorted_list(ports: Counter[str]) -> List[str]:
    def _port_sort_key(s: str) -> Tuple[int, str]:
        m = re.match(r"^(\d+)/(tcp|udp)$", s)
        if m:
            return int(m.group(1)), m.group(2)
        return 999999, s

    return sorted(ports.keys(), key=_port_sort_key)


def infer_device_type(h: HostStats) -> str:
    sp = set(h.server_ports.keys())

    def has(port: int, proto: str) -> bool:
        return f"{port}/{proto}" in sp

    if has(9100, "tcp") or has(631, "tcp") or has(515, "tcp") or has(515, "udp") or has(631, "udp"):
        return "printer"
    if has(5060, "udp") or has(5060, "tcp") or has(5061, "tcp") or has(5061, "udp"):
        return "ip_phone"
    if has(554, "tcp") or has(554, "udp"):
        return "camera"
    if has(67, "udp") or has(547, "udp") or (has(53, "udp") and has(67, "udp")):
        return "router"
    for p in (22, 80, 443, 445, 3389, 25, 110, 143, 3306, 5432, 1433, 5985, 5986, 6379, 8080, 8443):
        if has(p, "tcp") or has(p, "udp"):
            return "server"
    if h.client_ports and not h.server_ports:
        return "workstation"
    return "unknown"


@dataclass
class DiagramHost:
    ip: str
    mac: Optional[str]
    name: Optional[str]
    names: List[str]
    server_ports: List[str]
    client_ports: List[str]
    tx_bytes: int
    rx_bytes: int
    peers_tx: List[Tuple[str, int]]
    peers_rx: List[Tuple[str, int]]

    @property
    def total_bytes(self) -> int:
        return self.tx_bytes + self.rx_bytes

    def label_text(self, max_ports: int, show_client_ports: bool) -> str:
        lines: List[str] = []
        if self.name and self.name != self.ip:
            lines.append(self.name)
        lines.append(self.ip)
        if self.mac:
            lines.append(f"MAC {self.mac}")

        if self.server_ports:
            srv = ", ".join(self.server_ports[:max_ports])
            if len(self.server_ports) > max_ports:
                srv += ", …"
            lines.append(f"Srv: {srv}")

        if show_client_ports and self.client_ports:
            cli = ", ".join(self.client_ports[:max_ports])
            if len(self.client_ports) > max_ports:
                cli += ", …"
            lines.append(f"Cli: {cli}")

        return "\n".join(lines)

    def tooltip_text(self, max_peer_lines: int = 0, show_client_ports: bool = False) -> str:
        lines: List[str] = []
        if self.names:
            lines.append("Names:")
            for n in self.names:
                lines.append(f"  {n}")
            lines.append("")
        if self.name:
            lines.append(f"Name: {self.name}")
        if self.mac:
            lines.append(f"MAC: {self.mac}")
        lines.append(f"IP: {self.ip}")
        lines.append(f"TX: {_human_bytes(self.tx_bytes)}")
        lines.append(f"RX: {_human_bytes(self.rx_bytes)}")
        lines.append(f"Total: {_human_bytes(self.total_bytes)}")

        if self.server_ports:
            lines.append("")
            lines.append("Services hosted (inferred):")
            lines.extend(self.server_ports)

        if show_client_ports and self.client_ports:
            lines.append("")
            lines.append("Services attempted (inferred):")
            lines.extend(self.client_ports)

        tx_map = dict(self.peers_tx)
        rx_map = dict(self.peers_rx)
        peers = set(tx_map) | set(rx_map)
        if peers:
            lines.append("")
            lines.append("Peers (TX/RX/Total):")
            peer_rows: List[Tuple[str, int, int, int]] = []
            for p in peers:
                tx = int(tx_map.get(p, 0))
                rx = int(rx_map.get(p, 0))
                peer_rows.append((p, tx, rx, tx + rx))
            peer_rows.sort(key=lambda t: (t[3], t[0]), reverse=True)
            if max_peer_lines and max_peer_lines > 0:
                peer_rows = peer_rows[:max_peer_lines]
            for p, tx, rx, total in peer_rows:
                lines.append(f"{p}: TX {_human_bytes(tx)} / RX {_human_bytes(rx)} / Total {_human_bytes(total)}")

        return "\n".join(lines)


def hosts_to_diagram_hosts(hosts: Dict[str, HostStats]) -> List[DiagramHost]:
    dhs: List[DiagramHost] = []
    for ip, hs in hosts.items():
        dhs.append(
            DiagramHost(
                ip=ip,
                mac=hs.best_mac(),
                name=hs.best_name(),
                names=sorted(hs.hostnames),
                server_ports=_ports_to_sorted_list(hs.server_ports),
                client_ports=_ports_to_sorted_list(hs.client_ports),
                tx_bytes=hs.tx_bytes,
                rx_bytes=hs.rx_bytes,
                peers_tx=sorted(hs.peers_tx.items(), key=lambda kv: kv[1], reverse=True),
                peers_rx=sorted(hs.peers_rx.items(), key=lambda kv: kv[1], reverse=True),
            )
        )

    dhs.sort(key=lambda h: (h.total_bytes, h.ip), reverse=True)
    return dhs


# ---------------------------------------------------------------------------
# draw.io (multi-page) generation
# ---------------------------------------------------------------------------


def _page_link(page_id: str) -> str:
    # internal page link format: data:page/id,<page id>
    return f"data:page/id,{page_id}"


def _safe_page_name(s: str) -> str:
    # keep names readable; diagrams.net allows ':' but avoid very long names.
    s = s.strip()
    if len(s) > 60:
        s = s[:57] + "…"
    return s or "Page"


def _host_page_name(dh: DiagramHost) -> str:
    # Prefer hostname, but always include IP.
    if dh.name and dh.name != dh.ip:
        return _safe_page_name(f"{dh.name} ({dh.ip})")
    return _safe_page_name(dh.ip)


def _grid_layout(n: int, node_w: int, node_h: int, max_cols: int) -> Tuple[int, int]:
    if n <= 0:
        return 1, 1
    cols = min(max_cols, max(1, math.ceil(math.sqrt(n))))
    rows = max(1, math.ceil(n / cols))
    return cols, rows


def _add_mxcell_vertex(
    root: ET.Element,
    cell_id: str,
    value: str,
    style: str,
    x: float,
    y: float,
    w: float,
    h: float,
    parent: str = "1",
    link: Optional[str] = None,
) -> ET.Element:
    attrs = {"id": cell_id, "value": value, "style": style, "vertex": "1", "parent": parent}
    if link:
        attrs["link"] = link
    cell = ET.SubElement(root, "mxCell", attrs)
    ET.SubElement(
        cell,
        "mxGeometry",
        {"x": str(int(x)), "y": str(int(y)), "width": str(int(w)), "height": str(int(h)), "as": "geometry"},
    )
    return cell


def _edge_insert_index(root: ET.Element, base_layer_cell_id: str = "1") -> int:
    """Return an insertion index that keeps edges behind vertices ("To Back").

    In diagrams.net / mxGraph, sibling order controls z-order: earlier siblings render
    behind later ones. We therefore keep all edge cells as the first children under the
    page root (immediately after the base layer cell, usually id="1").
    """

    children = list(root)

    # Locate the base layer cell (normally id="1"). If not found, fall back to index 1.
    base_idx = 1
    for i, el in enumerate(children):
        if el.tag == "mxCell" and el.get("id") == base_layer_cell_id:
            base_idx = i
            break

    i = base_idx + 1
    # Keep edges grouped together at the back.
    while i < len(children):
        el = children[i]
        if el.tag == "mxCell" and el.get("edge") == "1":
            i += 1
            continue
        break
    return i


def _add_mxcell_edge(
    root: ET.Element,
    cell_id: str,
    value: str,
    style: str,
    source: str,
    target: str,
    parent: str = "1",
) -> ET.Element:
    """Add an edge and ensure it is placed *behind* other content.

    Requirement: network lines must be "To Back" so they don't cover host labels.
    """

    attrs = {
        "id": cell_id,
        "value": value,
        "style": style,
        "edge": "1",
        "parent": parent,
        "source": source,
        "target": target,
    }

    cell = ET.Element("mxCell", attrs)
    ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})

    # Insert directly after the base layer cell and any existing edges.
    root.insert(_edge_insert_index(root, base_layer_cell_id=parent), cell)
    return cell


def _new_diagram(mxfile: ET.Element, diagram_id: str, name: str, page_w: int, page_h: int) -> Tuple[ET.Element, int]:
    diagram = ET.SubElement(mxfile, "diagram", {"id": diagram_id, "name": name})
    model = ET.SubElement(
        diagram,
        "mxGraphModel",
        {
            "dx": "1200",
            "dy": "800",
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "1",
            "pageScale": "1",
            "pageWidth": str(page_w),
            "pageHeight": str(page_h),
            "math": "0",
            "shadow": "0",
        },
    )
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
    return root, 2


def _format_top_ports(counter: Counter[int], max_ports: int = 10) -> str:
    if not counter:
        return "None"
    items = counter.most_common(max_ports)
    parts = [str(p) for p, _ in items]
    if len(counter) > max_ports:
        parts.append(f"+{len(counter) - max_ports} more")
    return ", ".join(parts)


def _comm_tooltip(
    a_ip: str,
    b_ip: str,
    dir_comms: Dict[Tuple[str, str], CommDirStats],
    max_ports: int = 10,
) -> str:
    ab = dir_comms.get((a_ip, b_ip))
    ba = dir_comms.get((b_ip, a_ip))

    def line_dir(label: str, st: Optional[CommDirStats]) -> List[str]:
        if not st:
            return [f"{label}: 0B / 0 pkts"]
        return [
            f"{label}: {_human_bytes(st.bytes)} / {st.packets} pkts",
            f"  TCP dports: {_format_top_ports(st.tcp_dports, max_ports)}",
            f"  UDP dports: {_format_top_ports(st.udp_dports, max_ports)}",
        ]

    lines: List[str] = [f"{a_ip} <-> {b_ip}", "", *line_dir(f"{a_ip} -> {b_ip}", ab), "", *line_dir(f"{b_ip} -> {a_ip}", ba)]
    return "\n".join(lines)


def build_drawio_multipage(
    diagram_hosts: List[DiagramHost],
    hosts_raw: Dict[str, HostStats],
    dir_comms: Dict[Tuple[str, str], CommDirStats],
    out_path: str,
    max_overview_hosts: int = 200,
    max_label_ports: int = 6,
    max_peer_lines: int = 0,
    show_client_ports: bool = False,
) -> None:
    # Page IDs
    overview_page_id = str(uuid.uuid4())
    host_page_ids: Dict[str, str] = {dh.ip: str(uuid.uuid5(uuid.NAMESPACE_URL, f"host:{dh.ip}")) for dh in diagram_hosts}

    top_hosts = diagram_hosts[: max_overview_hosts]
    rest_hosts = diagram_hosts[max_overview_hosts:]

    remainder_page_id: Optional[str] = None
    if rest_hosts:
        remainder_page_id = str(uuid.uuid4())

    total_pages = 1 + len(diagram_hosts) + (1 if remainder_page_id else 0)

    mxfile = ET.Element(
        "mxfile",
        {
            "host": "app.diagrams.net",
            "modified": _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "agent": "pcap-to-drawio-multipage-fixed.py",
            "version": "22.0.8",
            "type": "device",
            "pages": str(total_pages),
        },
    )

    # ------------------------------------------------------------------
    # Overview page
    # ------------------------------------------------------------------

    node_w, node_h = 240, 125
    h_gap, v_gap = 40, 40
    margin = 60
    header_h = 120

    cols, rows = _grid_layout(len(top_hosts), node_w, node_h, max_cols=10)
    page_w = max(1000, margin * 2 + cols * node_w + (cols - 1) * h_gap)
    page_h = max(900, margin * 2 + header_h + rows * node_h + (rows - 1) * v_gap)

    root, next_id = _new_diagram(mxfile, overview_page_id, "Overview", page_w, page_h)

    # Branding/logo
    branding_id = str(next_id)
    next_id += 1
    brand_cell = ET.SubElement(
        root,
        "mxCell",
        {
            "id": branding_id,
            "value": branding_html(BRANDING_TEXT),
            "style": branding_style(),
            "vertex": "1",
            "parent": "1",
        },
    )
    ET.SubElement(
        brand_cell,
        "mxGeometry",
        {
            "x": "10",
            "y": "10",
            "width": "180",
            "height": "101",
            "as": "geometry",
        },
    )

    # Optional link to remainder page
    if remainder_page_id:
        link_id = str(next_id)
        next_id += 1
        _add_mxcell_vertex(
            root,
            link_id,
            html_label_with_tooltip(
                f"Other hosts ({len(rest_hosts)})",
                "Click to view hosts beyond the Top list",
            ),
            "text;html=1;strokeColor=none;fillColor=none;fontColor=#0197FF;fontSize=14;fontStyle=1;",
            x=page_w - 320,
            y=35,
            w=280,
            h=40,
            link=_page_link(remainder_page_id),
        )

    # Host nodes
    start_x = margin
    start_y = margin + header_h

    for idx, dh in enumerate(top_hosts):
        r = idx // cols
        c = idx % cols
        x = start_x + c * (node_w + h_gap)
        y = start_y + r * (node_h + v_gap)

        hs = hosts_raw.get(dh.ip)
        dtype = infer_device_type(hs) if hs else "unknown"
        style = style_for_device(dtype, clickable=True, focal=False)

        tooltip = dh.tooltip_text(max_peer_lines=max_peer_lines, show_client_ports=show_client_ports)
        label = dh.label_text(max_ports=max_label_ports, show_client_ports=show_client_ports)

        value = html_label_with_tooltip(label, tooltip)
        cell_id = str(next_id)
        next_id += 1
        _add_mxcell_vertex(
            root,
            cell_id,
            value,
            style,
            x=x,
            y=y,
            w=node_w,
            h=node_h,
            link=_page_link(host_page_ids[dh.ip]),
        )

    # ------------------------------------------------------------------
    # Per-host pages
    # ------------------------------------------------------------------

    # Map IP -> DiagramHost
    dh_map: Dict[str, DiagramHost] = {dh.ip: dh for dh in diagram_hosts}

    for dh in diagram_hosts:
        focal_ip = dh.ip
        page_id = host_page_ids[focal_ip]
        page_name = _host_page_name(dh)

        # Build peer list
        tx_map = dict(dh.peers_tx)
        rx_map = dict(dh.peers_rx)
        peers = sorted(set(tx_map) | set(rx_map), key=lambda p: (tx_map.get(p, 0) + rx_map.get(p, 0)), reverse=True)

        peer_node_w, peer_node_h = 240, 120
        focal_w, focal_h = 280, 140
        h_gap2, v_gap2 = 40, 40
        header_h2 = 130
        margin2 = 60

        cols2, rows2 = _grid_layout(len(peers), peer_node_w, peer_node_h, max_cols=8)
        inner_w = max(focal_w, cols2 * peer_node_w + (cols2 - 1) * h_gap2)
        inner_h = focal_h + (40 if peers else 0) + rows2 * peer_node_h + (rows2 - 1) * v_gap2

        page_w2 = max(1100, margin2 * 2 + inner_w)
        page_h2 = max(900, margin2 * 2 + header_h2 + inner_h)

        root2, next2 = _new_diagram(mxfile, page_id, page_name, page_w2, page_h2)

        # Branding/logo
        branding_id = str(next2)
        next2 += 1
        brand_cell = ET.SubElement(
            root2,
            "mxCell",
            {
                "id": branding_id,
                "value": branding_html(BRANDING_TEXT),
                "style": branding_style(),
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            brand_cell,
            "mxGeometry",
            {
                "x": "10",
                "y": "10",
                "width": "180",
                "height": "101",
                "as": "geometry",
            },
        )

        # Back link
        back_id = str(next2)
        next2 += 1
        _add_mxcell_vertex(
            root2,
            back_id,
            html_label_with_tooltip("Back to Overview", "Return to the Top hosts overview page"),
            "text;html=1;strokeColor=none;fillColor=none;fontColor=#0197FF;fontSize=14;fontStyle=1;",
            x=page_w2 - 300,
            y=35,
            w=260,
            h=40,
            link=_page_link(overview_page_id),
        )

        # Focal host node
        focal_x = (page_w2 - focal_w) / 2
        focal_y = margin2 + header_h2

        hs_focal = hosts_raw.get(focal_ip)
        dtype_focal = infer_device_type(hs_focal) if hs_focal else "unknown"
        focal_style = style_for_device(dtype_focal, clickable=True, focal=True)
        focal_tip = dh.tooltip_text(max_peer_lines=max_peer_lines, show_client_ports=show_client_ports)
        focal_label = dh.label_text(max_ports=max_label_ports, show_client_ports=show_client_ports)
        focal_value = html_label_with_tooltip(focal_label, focal_tip)

        focal_cell_id = str(next2)
        next2 += 1
        _add_mxcell_vertex(
            root2,
            focal_cell_id,
            focal_value,
            focal_style,
            x=focal_x,
            y=focal_y,
            w=focal_w,
            h=focal_h,
            link=_page_link(page_id),
        )

        # Peer nodes
        peer_start_x = (page_w2 - inner_w) / 2
        peer_start_y = focal_y + focal_h + (40 if peers else 0)

        peer_cell_ids: Dict[str, str] = {}
        for idx, peer_ip in enumerate(peers):
            r = idx // cols2
            c = idx % cols2
            x = peer_start_x + c * (peer_node_w + h_gap2)
            y = peer_start_y + r * (peer_node_h + v_gap2)

            peer_dh = dh_map.get(peer_ip)
            if peer_dh is None:
                # Should not happen, but avoid crashing on weird edge cases.
                peer_dh = DiagramHost(
                    ip=peer_ip,
                    mac=None,
                    name=None,
                    names=[],
                    server_ports=[],
                    client_ports=[],
                    tx_bytes=0,
                    rx_bytes=0,
                    peers_tx=[],
                    peers_rx=[],
                )

            hs_peer = hosts_raw.get(peer_ip)
            dtype_peer = infer_device_type(hs_peer) if hs_peer else "unknown"
            peer_style = style_for_device(dtype_peer, clickable=True, focal=False)

            peer_tip = peer_dh.tooltip_text(max_peer_lines=max_peer_lines, show_client_ports=show_client_ports)
            peer_label = peer_dh.label_text(max_ports=max(3, max_label_ports // 2), show_client_ports=show_client_ports)
            peer_value = html_label_with_tooltip(peer_label, peer_tip)

            cell_id = str(next2)
            next2 += 1
            peer_cell_ids[peer_ip] = cell_id
            _add_mxcell_vertex(
                root2,
                cell_id,
                peer_value,
                peer_style,
                x=x,
                y=y,
                w=peer_node_w,
                h=peer_node_h,
                link=_page_link(host_page_ids.get(peer_ip, overview_page_id)),
            )

        # Edges (directional arrows)
        edge_style_base = (
            "edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;"
            "strokeColor=#00cc66;fontColor=#202124;strokeWidth=2;"
        )

        for peer_ip in peers:
            tx_b = int(tx_map.get(peer_ip, 0))
            rx_b = int(rx_map.get(peer_ip, 0))

            if tx_b <= 0 and rx_b <= 0:
                continue

            peer_cell_id = peer_cell_ids[peer_ip]

            # Decide direction and arrowheads
            if tx_b > 0 and rx_b > 0:
                source = focal_cell_id
                target = peer_cell_id
                style = edge_style_base + "endArrow=block;startArrow=block;"
                label = f"TX {_human_bytes(tx_b)} | RX {_human_bytes(rx_b)}"
            elif tx_b > 0:
                source = focal_cell_id
                target = peer_cell_id
                style = edge_style_base + "endArrow=block;startArrow=none;"
                label = f"TX {_human_bytes(tx_b)}"
            else:
                source = peer_cell_id
                target = focal_cell_id
                style = edge_style_base + "endArrow=block;startArrow=none;"
                label = f"RX {_human_bytes(rx_b)}"

            tip = _comm_tooltip(focal_ip, peer_ip, dir_comms)
            value = html_edge_label_with_tooltip(label, tip)

            eid = str(next2)
            next2 += 1
            _add_mxcell_edge(root2, eid, value, style, source=source, target=target)

    # ------------------------------------------------------------------
    # Remainder page (last)
    # ------------------------------------------------------------------

    if remainder_page_id:
        node_w3, node_h3 = 240, 125
        h_gap3, v_gap3 = 40, 40
        margin3 = 60
        header_h3 = 120

        cols3, rows3 = _grid_layout(len(rest_hosts), node_w3, node_h3, max_cols=10)
        page_w3 = max(1000, margin3 * 2 + cols3 * node_w3 + (cols3 - 1) * h_gap3)
        page_h3 = max(900, margin3 * 2 + header_h3 + rows3 * node_h3 + (rows3 - 1) * v_gap3)

        root3, next3 = _new_diagram(mxfile, remainder_page_id, "Other Hosts", page_w3, page_h3)

        # Branding/logo
        branding_id = str(next3)
        next3 += 1
        brand_cell = ET.SubElement(
            root3,
            "mxCell",
            {
                "id": branding_id,
                "value": branding_html(BRANDING_TEXT),
                "style": branding_style(),
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            brand_cell,
            "mxGeometry",
            {
                "x": "10",
                "y": "10",
                "width": "180",
                "height": "101",
                "as": "geometry",
            },
        )

        back3_id = str(next3)
        next3 += 1
        _add_mxcell_vertex(
            root3,
            back3_id,
            html_label_with_tooltip("Back to Overview", "Return to the Top hosts overview page"),
            "text;html=1;strokeColor=none;fillColor=none;fontColor=#0197FF;fontSize=14;fontStyle=1;",
            x=page_w3 - 300,
            y=35,
            w=260,
            h=40,
            link=_page_link(overview_page_id),
        )

        start_x = margin3
        start_y = margin3 + header_h3
        for idx, dh in enumerate(rest_hosts):
            r = idx // cols3
            c = idx % cols3
            x = start_x + c * (node_w3 + h_gap3)
            y = start_y + r * (node_h3 + v_gap3)

            hs = hosts_raw.get(dh.ip)
            dtype = infer_device_type(hs) if hs else "unknown"
            style = style_for_device(dtype, clickable=True, focal=False)

            tooltip = dh.tooltip_text(max_peer_lines=max_peer_lines, show_client_ports=show_client_ports)
            label = dh.label_text(max_ports=max_label_ports, show_client_ports=show_client_ports)
            value = html_label_with_tooltip(label, tooltip)

            cid = str(next3)
            next3 += 1
            _add_mxcell_vertex(
                root3,
                cid,
                value,
                style,
                x=x,
                y=y,
                w=node_w3,
                h=node_h3,
                link=_page_link(host_page_ids[dh.ip]),
            )

    # Write file
    try:
        ET.indent(mxfile)  # type: ignore[attr-defined]
    except Exception:
        pass

    xml_bytes = ET.tostring(mxfile, encoding="utf-8", xml_declaration=True)
    with open(out_path, "wb") as f:
        f.write(xml_bytes)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Convert PCAP/PCAPNG to a multi-page draw.io network diagram.")
    ap.add_argument("input", help="Input .pcap or .pcapng")
    ap.add_argument("output", help="Output .drawio")
    ap.add_argument("--max-overview-hosts", type=int, default=200, help="Top N hosts to show on Overview (default: 200)")
    ap.add_argument("--max-label-ports", type=int, default=6, help="Max ports shown in host label (default: 6)")
    ap.add_argument(
        "--max-peer-lines",
        type=int,
        default=0,
        help="Max peer lines in host tooltip (0 = all, default: 0)",
    )
    ap.add_argument(
        "--show-client-ports",
        action="store_true",
        help="Include inferred client/attempted ports in labels/tooltips",
    )

    args = ap.parse_args(argv)

    hosts, dir_comms = analyze_capture(args.input)
    diagram_hosts = hosts_to_diagram_hosts(hosts)

    print(f"Observed hosts (unique src/dst IPs): {len(diagram_hosts)}")

    build_drawio_multipage(
        diagram_hosts,
        hosts_raw=hosts,
        dir_comms=dir_comms,
        out_path=args.output,
        max_overview_hosts=args.max_overview_hosts,
        max_label_ports=args.max_label_ports,
        max_peer_lines=args.max_peer_lines,
        show_client_ports=args.show_client_ports,
    )

    print(f"Wrote: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
