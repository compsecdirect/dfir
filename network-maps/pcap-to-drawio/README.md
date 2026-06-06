# 🗺️ Network Maps: pcap to drawio

Turn **PCAP / PCAPNG packet captures** into clean, interactive **diagrams.net / draw.io** network diagrams — automatically. ✨  
This version generates a **multi-page** `.drawio` file: an Overview page + one page per host.

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](#requirements)
[![Dependency](https://img.shields.io/badge/Dependency-dpkt-6A5ACD)](#requirements)
[![Output](https://img.shields.io/badge/Output-.drawio-orange?logo=diagramsdotnet&logoColor=white)](#opening-the-diagram)
[![Input](https://img.shields.io/badge/Input-PCAP%20%7C%20PCAPNG-4CAF50)](#usage)

---
![](https://github.com/compsecdirect/dfir/blob/main/network-maps/pcap-to-drawio/pcap-to-drawio.png)

## 🚀 What it does

✅ Converts `.pcap` / `.pcapng` into a `.drawio` diagram with:

- 🧾 **Observed host inventory**: unique IPv4/IPv6 hosts from *actual L3 src/dst IPs* seen in the capture  
  (no host creation from DNS-only answers).
- 🧷 **MAC addresses** per host (most-seen MAC when link-layer provides it; supports common link types).
- 🏷️ **Hostname enrichment** (best-effort):
  - DNS A/AAAA/PTR answers
  - DHCP hostname option (when present)
  - HTTP `Host:` header (no stream reassembly; best-effort)
  - TLS SNI from ClientHello (no stream reassembly; best-effort)
- 🔍 **Service inference** (“open ports”, passive): server-side ports inferred from observed TCP/UDP behavior.
- 🧠 **Device icons/shapes** using built-in draw.io stencils (MSCAE/Cisco/AWS/iOS7), based on port/service heuristics.
- 🧩 **Multi-page navigation**
  - **Overview page**: shows only the **Top N hosts (default 200)** by traffic (TX+RX), sorted greatest → least
  - **Per-host pages**: one page per host, showing all communicating peers with **arrowed edges** (directional traffic)
  - **Remainder page**: if there are more than Top N hosts, the rest are shown on a final “Other Hosts” page
- 🧱 “**To Back**” rendering for network lines so nodes/labels stay readable above links
- 🏷️ Embedded **branding banner** (logo + text) inside the Python file (no external assets)

---

## ✨ Preview (what you’ll get)

- 📄 An **Overview** page with the biggest talkers first
- 🖱️ Click a host → jump to its detail page
- 🧷 Hover nodes/edges for traffic summaries and inferred services

> Tip: Large captures can produce **many pages** (one per host).  
> If diagrams.net gets sluggish, start with a filtered PCAP or reduce the host count using `--max-overview-hosts`.

---

## 📦 Requirements

- 🐍 Python **3.12+**
- 📦 `dpkt`

Install dependency:

```bash
pip install dpkt
```

---

## 🛠️ Installation

Place `pcap-to-drawio-multipage-fixed.py` anywhere you like, then run:

```bash
python3 pcap-to-drawio.py --help
```

---

## ▶️ Usage

```bash
python3 pcap-to-drawio.py capture.pcapng output.drawio
# or
python3 pcap-to-drawio.py capture.pcap output.drawio
```

---

## 🧰 CLI Options

```text
positional arguments:
  input                 Input .pcap or .pcapng
  output                Output .drawio

optional arguments:
  --max-overview-hosts N   Top N hosts to show on Overview (default: 200)
  --max-label-ports N      Max ports shown in host label (default: 6)
  --max-peer-lines N       Max peer lines in host tooltip (0 = all, default: 0)
  --show-client-ports      Include inferred client/attempted ports in labels/tooltips
```

Examples:

```bash
# Keep Overview to top 100 talkers
python3 pcap-to-drawio.py capture.pcapng map.drawio --max-overview-hosts 100

# Reduce label clutter; show all peers in tooltip
python3 pcap-to-drawio.py capture.pcapng map.drawio --max-label-ports 3 --max-peer-lines 0

# Include client/attempted ports in labels/tooltips
python3 pcap-to-drawio.py capture.pcapng map.drawio --show-client-ports
```

---

## 📂 Pages and navigation

### 1) Overview page (main page)

- Shows only the **Top N** hosts by total traffic (TX+RX), sorted highest → lowest.
- Each node is clickable and links to the host’s detail page.

### 2) Per-host pages (one page per host)

- The “focus” host is highlighted.
- Every peer that communicated with the host is included on that page.
- **Directional arrows** represent the direction of observed traffic.
- Node tooltips summarize traffic totals + inferred services; edge tooltips summarize the communications.

### 3) Other Hosts page (remainder)

If total observed hosts exceed Top N, a final page is created that contains the remaining hosts in a grid.

---

## 🧩 Device icon/shape mapping

This project maps inferred device types to draw.io shapes:

| Type 🧠        | draw.io shape                                 |
| -------------- | --------------------------------------------- |
| 🌐 network     | `mxgraph.mscae.enterprise.internet`           |
| 📡 router      | `mxgraph.mscae.enterprise.router`             |
| 🔀 switch      | `mxgraph.mscae.enterprise.device`             |
| 🧱 firewall    | `mxgraph.cisco_safe.security_icons.firewall`  |
| 📶 wireless_ap | `mxgraph.ios7.icons.wifi`                     |
| 🗄️ server     | `mxgraph.mscae.enterprise.server_generic`     |
| 💻 workstation | `mxgraph.mscae.enterprise.workstation_client` |
| 🖨️ printer    | `mxgraph.cisco19.printer`                     |
| ☎️ ip_phone    | `mxgraph.cisco19.ip_phone`                    |
| 📷 camera      | `mxgraph.aws4.camera2`                        |
| ❓ unknown     | `mxgraph.mscae.enterprise.device`             |

Heuristics are based on **observed server-side ports** (and optionally client behavior), e.g. RTSP → camera, SIP → phone, IPP/9100 → printer, DHCP/DNS → router, etc.

---

## 🧷 Tooltips (hover behavior)

### Host nodes

Hover over a host node to see:

- Names seen (DNS/DHCP/HTTP Host/TLS SNI where applicable)
- MAC address (if available)
- TX / RX / Total bytes
- **Services hosted (inferred)**: server ports observed for that host
- Peers summary (TX/RX/Total per peer), optionally limited by `--max-peer-lines`

### Edges (per-host pages)

Hover over an edge to see a directional communication summary (bytes and ports observed between the two hosts).

---

## 🧠 How “open ports” are inferred (important)

PCAP/PCAPNG files do **not** directly enumerate open ports like a scanner would.

This tool infers “services hosted” only from what the capture **actually shows**, for example:

- **TCP**
  - SYN/SYN-ACK patterns when present
  - mid-stream/payload heuristics for partial captures
- **UDP**
  - request/response direction + known service ports + packet/byte thresholds

So a port listed in the diagram means: **traffic consistent with that service was observed** — not that the port is guaranteed open on the host right now.

---

## 🧾 Opening the diagram

Open the resulting `.drawio` file in diagrams.net:

- Online: `https://app.diagrams.net/`
- Desktop app: diagrams.net (draw.io)

Then:

**File → Open from Device** → select your `.drawio`.

---

## 🤝 Contributing

PRs welcome! 💚

Ideas:

- Improve device/service heuristics
- Add more link-type support (additional pcap/pcapng datalinks)
- Smarter clustering/layout for very large captures
- Optional filters (exclude multicast, ignore RFC1918/ULA, etc.)

