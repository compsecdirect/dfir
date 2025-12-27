#!/usr/bin/env python3
"""
nmap-to-drawio.py
Load Nmap output and generate a diagrams.net / draw.io (.drawio) network diagram.

Features
- Supports Nmap Normal (-oN), Grepable (-oG), and XML (-oX) outputs (auto-detected).
- Layout scales with number of hosts (canvas grows; nodes/gaps shrink for very large scans).
- Each host node shows open ports as a hover tooltip (HTML label with title="...").
- Hosts are placed on an evenly spaced grid to keep the diagram readable.
- Optional central "Network" node with links to each host.
- OS identification of Nmap XML -oX with -O or nmap output with -O included in tooltips.
- Device shapes mapped to your requested draw.io shape libraries.

Usage:
  python3 nmap-to-drawio.py scan.txt out.drawio
  python3 nmap-to-drawio.py scan.xml out.drawio --no-edges
  cat scan.txt | python3 nmap2drawio.py - out.drawio

Open the resulting .drawio file at https://app.diagrams.net/ (File -> Open from Device).
"""

import argparse
import html
import math
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

BRANDING_TEXT = "Network Maps: nmap to draw.io by CompSec Direct® CompSecDirect.com"

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


# -----------------------------
# Nmap parsing
# -----------------------------

_RE_NORMAL_HOST = re.compile(r"^Nmap scan report for (.+)$")
_RE_PORT_LINE = re.compile(
    r"^(?P<port>\d+)\/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)(?P<rest>.*)$",
    re.IGNORECASE,
)
_RE_GREPPABLE_HOST = re.compile(r"^Host:\s+(?P<ip>\S+)\s+\((?P<name>.*?)\)\s+Ports:\s+(?P<ports>.*)$")
_RE_OS_GUESSES = re.compile(r"^(Aggressive OS guesses|OS guesses):\s*(.+)$", re.IGNORECASE)
_RE_OS_DETAILS = re.compile(r"^OS details:\s*(.+)$", re.IGNORECASE)
_RE_RUNNING = re.compile(r"^Running:\s*(.+)$", re.IGNORECASE)
_RE_SERVICE_INFO = re.compile(r"^Service Info:\s*(.+)$", re.IGNORECASE)

def _parse_first_guess_with_accuracy(s: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Parse strings like:
      'Linux 5.4 (95%), Linux 5.10 (93%), ...'
    Return (first_guess_text, accuracy_int_or_None)
    """
    if not s:
        return None, None

    first = s.split(",")[0].strip()

    m = re.search(r"\((\d+)%\)", first)
    acc = int(m.group(1)) if m else None

    # remove "(95%)" from the guess text
    guess = re.sub(r"\s*\(\d+%\)\s*", "", first).strip()
    return (guess or None), acc

def _maybe_set_os(current, guess: Optional[str], acc: Optional[int]) -> None:
    """
    Set OS guess on current host if:
    - not set yet, OR
    - new accuracy is higher than existing accuracy
    """
    if not guess:
        return
    if current.os_guess is None:
        current.os_guess = guess
        current.os_accuracy = acc
        return
    # Prefer higher confidence when available
    if acc is not None and (current.os_accuracy is None or acc > current.os_accuracy):
        current.os_guess = guess
        current.os_accuracy = acc


@dataclass
class Host:
    ip: str
    name: Optional[str] = None
    ports: List[str] = field(default_factory=list)
    os_guess: Optional[str] = None
    os_accuracy: Optional[int] = None

    @property
    def display_label(self) -> str:
        if self.name and self.name != self.ip:
            return f"{self.name}\n{self.ip}"
        return self.ip

    @property
    def tooltip_text(self) -> str:
        lines: List[str] = []
        if self.os_guess:
            acc = f" ({self.os_accuracy}%)" if self.os_accuracy is not None else ""
            lines.append(f"OS: {self.os_guess}{acc}")
        else:
            lines.append("OS: Unknown")

        if self.ports:
            lines.append("Open ports:")
            lines.extend(self.ports)
        else:
            lines.append("No open ports parsed")
        return "\n".join(lines)


def _looks_like_xml(text: str) -> bool:
    s = text.lstrip()
    return s.startswith("<?xml") or s.startswith("<nmaprun")


def _looks_like_grepable(text: str) -> bool:
    return bool(re.search(r"^Host:\s+\S+", text, flags=re.MULTILINE))


def parse_nmap(text: str) -> List[Host]:
    text = text.replace("\r\n", "\n")

    if _looks_like_xml(text):
        return parse_nmap_xml(text)
    if _looks_like_grepable(text):
        hosts = parse_nmap_grepable(text)
        if hosts:
            return hosts
    return parse_nmap_normal(text)


def parse_nmap_normal(text: str) -> List[Host]:
    hosts: List[Host] = []
    current: Optional[Host] = None

    for line in text.splitlines():
        line = line.rstrip("\n")

        m_host = _RE_NORMAL_HOST.match(line)
        if m_host:
            if current is not None:
                hosts.append(current)

            raw = m_host.group(1).strip()
            name = None
            ip = raw
            m_ip = re.search(r"\(([^)]+)\)$", raw)
            if m_ip:
                ip = m_ip.group(1).strip()
                name = raw[: raw.rfind("(")].strip()
            else:
                if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw):
                    name = raw
            current = Host(ip=ip, name=name, ports=[])
            continue

        if current is None:
            continue

        m_port = _RE_PORT_LINE.match(line)
        # OS detection (normal output, requires nmap -O)
        if current is not None:
            m = _RE_OS_GUESSES.match(line)
            if m:
                guess, acc = _parse_first_guess_with_accuracy(m.group(2))
                _maybe_set_os(current, guess, acc)
                continue

            m = _RE_OS_DETAILS.match(line)
            if m:
                _maybe_set_os(current, m.group(1).strip(), None)
                continue

            m = _RE_RUNNING.match(line)
            if m:
                _maybe_set_os(current, m.group(1).strip(), None)
                continue

            m = _RE_SERVICE_INFO.match(line)
            if m:
                # Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
                blob = m.group(1)
                m2 = re.search(r"\bOS:\s*([^;]+)", blob, flags=re.IGNORECASE)
                if m2:
                    _maybe_set_os(current, m2.group(1).strip(), None)
                # no continue; allow port parsing too if present (usually not)

        if m_port:
            port = m_port.group("port")
            proto = m_port.group("proto")
            service = m_port.group("service")
            rest = (m_port.group("rest") or "").strip()
            entry = f"{port}/{proto} {service}" + (f" {rest}" if rest else "")
            current.ports.append(entry)

    if current is not None:
        hosts.append(current)

    for h in hosts:
        seen = set()
        uniq = []
        for p in h.ports:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        h.ports = uniq

    return merge_hosts_by_ip(hosts)


def parse_nmap_grepable(text: str) -> List[Host]:
    hosts: List[Host] = []
    for line in text.splitlines():
        line = line.strip()
        m = _RE_GREPPABLE_HOST.match(line)
        if not m:
            continue

        ip = m.group("ip").strip()
        name = m.group("name").strip() or None
        ports_blob = m.group("ports").strip()

        # OS detection (grepable output often includes "OS: ...")
        os_guess: Optional[str] = None
        os_accuracy: Optional[int] = None

        # Many -oG lines are tab-separated; OS field usually appears as "OS: ..."
        m_os = re.search(r"\bOS:\s*([^\t]+)$", line, flags=re.IGNORECASE)
        if m_os:
            os_guess, os_accuracy = _parse_first_guess_with_accuracy(m_os.group(1).strip())

        ports: List[str] = []
        for chunk in ports_blob.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split("/")
            if len(parts) < 5:
                continue
            port, state, proto = parts[0], parts[1], parts[2]
            service = parts[4] if parts[4] else "unknown"
            if state != "open":
                continue
            ports.append(f"{port}/{proto} {service}")
        hosts.append(Host(ip=ip, name=name, ports=ports, os_guess=os_guess, os_accuracy=os_accuracy))

    return merge_hosts_by_ip(hosts)


def parse_nmap_xml(text: str) -> List[Host]:
    root = ET.fromstring(text)
    hosts: List[Host] = []

    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue

        ip = None
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        name = None
        hn = h.find("hostnames")
        if hn is not None:
            hostnames = hn.findall("hostname")
            if hostnames:
                name = hostnames[0].get("name")

        # Best OS match (requires -O)
        os_guess = None
        os_accuracy = None
        os_el = h.find("os")
        if os_el is not None:
            best = None
            best_acc = -1
            for m in os_el.findall("osmatch"):
                acc_s = m.get("accuracy", "0")
                try:
                    acc = int(acc_s)
                except ValueError:
                    acc = 0
                if acc > best_acc:
                    best_acc = acc
                    best = m
            if best is not None:
                os_guess = (best.get("name") or "").strip() or None
                os_accuracy = best_acc if best_acc >= 0 else None

        ports: List[str] = []
        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                proto = p.get("protocol") or "tcp"
                portid = p.get("portid") or "?"
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = p.find("service")
                svc_name = svc.get("name") if svc is not None and svc.get("name") else "unknown"
                extra = []
                if svc is not None:
                    for k in ("product", "version", "extrainfo"):
                        v = svc.get(k)
                        if v:
                            extra.append(v)
                tail = (" " + " ".join(extra)) if extra else ""
                ports.append(f"{portid}/{proto} {svc_name}{tail}".strip())

        hosts.append(Host(ip=ip, name=name, ports=ports, os_guess=os_guess, os_accuracy=os_accuracy))

    return merge_hosts_by_ip(hosts)


def merge_hosts_by_ip(hosts: List[Host]) -> List[Host]:
    by_ip: Dict[str, Host] = {}
    for h in hosts:
        if h.ip not in by_ip:
            by_ip[h.ip] = Host(
                ip=h.ip,
                name=h.name,
                ports=list(h.ports),
                os_guess=h.os_guess,
                os_accuracy=h.os_accuracy,
            )
        else:
            existing = by_ip[h.ip]
            if not existing.name and h.name:
                existing.name = h.name

            # Prefer higher-accuracy OS guess if available
            if h.os_guess:
                if existing.os_guess is None:
                    existing.os_guess = h.os_guess
                    existing.os_accuracy = h.os_accuracy
                else:
                    if h.os_accuracy is not None and (existing.os_accuracy is None or h.os_accuracy > existing.os_accuracy):
                        existing.os_guess = h.os_guess
                        existing.os_accuracy = h.os_accuracy

            for p in h.ports:
                if p not in existing.ports:
                    existing.ports.append(p)

    return list(by_ip.values())



# -----------------------------
# Shape mapping / device inference
# -----------------------------

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


def infer_device_type(host: Host) -> str:
    osn = (host.os_guess or "").lower()

    def has_port(p: int) -> bool:
        for e in host.ports:
            m = re.match(r"^(\d+)/", e)
            if m and int(m.group(1)) == p:
                return True
        return False

    def has_service(rx: str) -> bool:
        r = re.compile(rx, re.I)
        return any(r.search(e) for e in host.ports)

    if "firewall" in osn:
        return "firewall"
    if "router" in osn or "cisco ios" in osn or "juniper" in osn:
        return "router"
    if "switch" in osn:
        return "switch"
    if "wireless" in osn or "access point" in osn:
        return "wireless_ap"

    if has_port(9100) or has_port(631) or has_port(515) or has_service(r"printer|ipp"):
        return "printer"
    if has_port(5060) or has_port(5061) or has_service(r"\bsip\b"):
        return "ip_phone"
    if has_port(554) or has_service(r"\brtsp\b"):
        return "camera"

    if has_port(3389) or has_service(r"\brdp\b"):
        if "server" in osn:
            return "server"
        return "workstation"
    if has_port(445) or has_service(r"\bsmb\b"):
        if "server" in osn:
            return "server"
        if "windows" in osn:
            return "workstation"

    if "windows" in osn:
        return "workstation"
    if "linux" in osn or "unix" in osn:
        return "server"

    return "unknown"


def style_for_device(device_type: str) -> str:
    shape = SHAPES.get(device_type, SHAPES["unknown"])
    return (
        f"shape={shape};"
        "html=1;"
        "whiteSpace=wrap;"
        "align=center;"
        "verticalAlign=middle;"
        "strokeWidth=1;"
    )


# -----------------------------
# Draw.io XML generation
# -----------------------------

def compute_layout(n: int) -> Tuple[int, int, float, float, float, float]:
    if n <= 0:
        return 1, 1, 160, 70, 40, 40

    cols = max(1, math.ceil(math.sqrt(n)))
    rows = max(1, math.ceil(n / cols))

    scale = 1.0
    if n > 30:
        scale = 0.85
    if n > 80:
        scale = 0.7
    if n > 150:
        scale = 0.6

    node_w = 160 * scale
    node_h = 70 * scale
    h_gap = 40 * scale
    v_gap = 40 * scale

    return cols, rows, node_w, node_h, h_gap, v_gap


def html_label_with_tooltip(label_text: str, tooltip_text: str) -> str:
    """
    Heading 3-ish, font color #00CC66, background #000000.
    Tooltip stays in title="...".
    """
    safe_label = html.escape(label_text).replace("\n", "<br/>")
    safe_tip = html.escape(tooltip_text).replace("\n", "&#10;")
    return (
        f'<div title="{safe_tip}" style="text-align:center;">'
        f'<span style="display:inline-block;'
        f'background:#000000;'
        f'color:#00CC66;'
        f'padding:3px 8px;'
        f'border-radius:6px;'
        f'font-size:18px;'
        f'font-weight:600;'
        f'line-height:1.2;">{safe_label}</span>'
        f"</div>"
    )


def build_drawio(hosts: List[Host], page_name: str = "Page-1", add_network_node: bool = True) -> str:
    """
    "To Front" guarantee:
      - Write edges FIRST
      - Then write network vertex (hub)
      - Then write host vertices
    """
    n = len(hosts)
    cols, rows, node_w, node_h, h_gap, v_gap = compute_layout(n)

    margin = 50
    top_extra = 130 if add_network_node else 40

    width = margin * 2 + cols * node_w + (cols - 1) * h_gap
    height = margin * 2 + top_extra + rows * node_h + (rows - 1) * v_gap

    mxfile = ET.Element(
        "mxfile",
        {
            "host": "app.diagrams.net",
            "modified": "",
            "agent": "nmap2drawio.py",
            "version": "22.0.8",
            "type": "device",
        },
    )

    diagram = ET.SubElement(mxfile, "diagram", {"id": str(uuid.uuid4()), "name": page_name})

    mxGraphModel = ET.SubElement(
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
            "pageWidth": str(int(max(850, math.ceil(width)))),
            "pageHeight": str(int(max(1100, math.ceil(height)))),
            "math": "0",
            "shadow": "0",
        },
    )

    root = ET.SubElement(mxGraphModel, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

    next_id = 2

    # Branding cell reserved first so it's always included
    branding_id = str(next_id)
    next_id += 1

    # Pre-allocate IDs
    network_id = None
    if add_network_node:
        network_id = str(next_id)
        next_id += 1

    host_id_map: Dict[int, str] = {}
    host_geom_map: Dict[int, Tuple[int, int]] = {}
    start_y = margin + (90 if add_network_node else 0) + 40

    for i, h in enumerate(hosts):
        r = i // cols
        c = i % cols
        x = margin + c * (node_w + h_gap)
        y = start_y + r * (node_h + v_gap)
        host_id_map[i] = str(next_id)
        next_id += 1
        host_geom_map[i] = (int(x), int(y))

    # 1) Edges first (behind)
    if add_network_node and network_id is not None:
        for i in range(n):
            edge_id = str(next_id)
            next_id += 1
            edge = ET.SubElement(
                root,
                "mxCell",
                {
                    "id": edge_id,
                    "value": "",
                    "style": "edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;endArrow=none;",
                    "edge": "1",
                    "parent": "1",
                    "source": network_id,
                    "target": host_id_map[i],
                },
            )
            ET.SubElement(edge, "mxGeometry", {"relative": "1", "as": "geometry"})

    # Branding (after edges => in front of lines, and always top-left)
    # A compact size that matches your uploaded logo aspect.
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

    # 2) Network hub (in front of edges)
    if add_network_node and network_id is not None:
        net_cell = ET.SubElement(
            root,
            "mxCell",
            {
                "id": network_id,
                "value": html_label_with_tooltip("Network", f"{n} host(s)"),
                "style": style_for_device("network") + "aspect=fixed;",
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            net_cell,
            "mxGeometry",
            {
                "x": str(int(width / 2 - 45)),
                "y": str(margin),
                "width": "90",
                "height": "60",
                "as": "geometry",
            },
        )

    # 3) Hosts last (To Front)
    for i, h in enumerate(hosts):
        cell_id = host_id_map[i]
        x, y = host_geom_map[i]

        dev_type = infer_device_type(h)
        style = style_for_device(dev_type)

        value = html_label_with_tooltip(h.display_label, h.tooltip_text)

        cell = ET.SubElement(
            root,
            "mxCell",
            {
                "id": cell_id,
                "value": value,
                "style": style,
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            {
                "x": str(x),
                "y": str(y),
                "width": str(int(node_w)),
                "height": str(int(node_h)),
                "as": "geometry",
            },
        )

    xml_bytes = ET.tostring(mxfile, encoding="utf-8", xml_declaration=True)
    return xml_bytes.decode("utf-8")


# -----------------------------
# CLI
# -----------------------------

def read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert Nmap output to a draw.io (.drawio) network diagram.")
    ap.add_argument("input", help="Nmap output file (-oN/-oG/-oX), or '-' for stdin")
    ap.add_argument("output", help="Output .drawio file path")
    ap.add_argument("--page-name", default="Page-1", help="Draw.io page name (default: Page-1)")
    ap.add_argument("--no-edges", action="store_true", help="Do not add a central Network node or edges")
    ap.add_argument("--sort", choices=["none", "ip", "name"], default="none", help="Optional host sort order")
    args = ap.parse_args()

    text = read_text(args.input)
    hosts = parse_nmap(text)

    if args.sort == "ip":
        hosts.sort(key=lambda h: tuple(int(x) if x.isdigit() else 0 for x in h.ip.split(".")) if "." in h.ip else (h.ip,))
    elif args.sort == "name":
        hosts.sort(key=lambda h: (h.name or "", h.ip))

    if not hosts:
        print("No hosts parsed from input. Check that the file contains Nmap output.", file=sys.stderr)
        return 2

    xml_out = build_drawio(hosts, page_name=args.page_name, add_network_node=(not args.no_edges))

    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(xml_out)

    print(f"Wrote {args.output} ({len(hosts)} host(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
