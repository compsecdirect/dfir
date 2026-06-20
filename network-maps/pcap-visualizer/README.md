# 🎞️ PCAP Visualizer — CompSec Direct

Replay packet captures as an accelerated **network traffic movie** with persistent hosts, DNS labels, device-shaped nodes, analyst findings, report exports, and multiple network-map layouts. ✨

[![App](https://img.shields.io/badge/App-Standalone%20HTML-38BDF8?logo=html5&logoColor=white)](#requirements)
[![Input](https://img.shields.io/badge/Input-PCAPNG%20%2F%20PCAP-4CAF50?logo=wireshark&logoColor=white)](#supported-captures)
[![Reports](https://img.shields.io/badge/Export-DOCX%20Findings-A78BFA?logo=libreoffice&logoColor=white)](#findings-and-reporting)
[![Privacy](https://img.shields.io/badge/Privacy-Local%20First-34D399?logo=firefoxbrowser&logoColor=white)](#privacy-and-security)

---

[![Watch the video](pcap-visualizer.png)](https://github.com/user-attachments/assets/02e5a513-ccc0-4043-94eb-45a391357a03)
## 🚀 What it does

✅ Turns packet capture files into an interactive live network replay with:

- 🕸️ **Persistent network maps** where hosts remain visible after discovery
- 🎯 **Finding Focus view** that centers a selected or marked findings host
- 📡 **Communication-weighted rings** where strongest peers are closest to the focus host and weaker peers are farther away
- 🧭 **Logical Groups view** that separates local devices from remote host groups by DNS domain or IP network prefix
- 📐 **Grid view** for stable left-to-right, top-to-bottom review
- 🔎 **Search and filters** for decoded text, hosts, DNS names, source, destination, ports, protocols, and services
- 🧠 **DNS, mDNS, LLMNR, and PCAPNG name-resolution labels** when available
- 🧩 **Device-shaped SVG nodes** inferred from local/remote role, DNS names, services, and observed ports
- 🖱️ **Drag-and-pin device placement** that stays fixed while the PCAP plays, pauses, rewinds, or fast-forwards
- 🚫 **Map exclusions** for hosts, IPs, MACs, and DNS names using pasted CSV/TSV/text lists or imported files
- ⭐ **Devices of Interest** for analyst triage and reporting
- 📝 **Queued Findings workflow** with final CompSec Direct branded Word-compatible `.docx` export
- 🖼️ **SVG and PNG snapshot export**

---

## ✨ Network map views

| View | What it is for |
| ---- | -------------- |
| **Timeline Grid** | Stable review of the active playback window with persistent hosts. |
| **Finding Focus** | Centers the selected or marked host. Hosts that communicated with it the most are placed closest; lower-volume peers move outward. |
| **Logical Groups** | Organizes local devices separately from remote groups. Remote hosts are grouped by DNS domain when known or by IP network prefix when names are unavailable. |

Use the **View** selector near the playback controls. Use **Focus host** to choose a findings host directly, or select a node and click **Mark Device of Interest**.

---

## 📦 Requirements

- 🌐 A modern desktop browser: Chrome, Edge, Firefox, Safari, or equivalent
- 📁 A `.pcapng` or classic `.pcap` file
- ✅ No server required for normal use
- ✅ No package manager required
- 🎨 Optional local Zen Dots font file placed beside the HTML for the Cyber theme

> For very large captures, a browser with more available memory will perform better.

---

## 🛠️ Installation

Download or copy the application files into a folder:

```text
pcap-visualizer
├── pcap-visualizer.html
├── app.js
├── pcapng-parser-core.js
├── template.html
└── README.md
```

Open the app directly in your browser:

```text
pcap-visualizer.html
```

Optional local web-server workflow:

```bash
cd pcap-visualizer
python3 -m http.server 8000
```

Then browse to:

```text
http://localhost:8000/pcap-visualizer.html
```

---

## ▶️ Usage

1. Open `pcap-visualizer.html`.
2. Drag a `.pcapng` or `.pcap` file into the page, or click **Open capture**.
3. Use the playback controls to replay the capture by timestamp.
4. Pick a network map view: **Timeline Grid**, **Finding Focus**, or **Logical Groups**.
5. Select an interesting host and click **Mark Device of Interest** near the top center.
6. Click **Add Finding** to queue the current timestamp, map image, label, notes, filters, focus host, and Devices of Interest.
7. Repeat for each finding.
8. Click **Final Export Report** to build one CompSec Direct branded `.docx` report from all queued findings.

---

## 🎛️ Controls

| Control | What it does |
| ------- | ------------ |
| **Play / Pause** | Starts or pauses timestamp-based replay. |
| **-10s / +10s** | Jumps backward or forward ten seconds. |
| **-1 window / +1 window** | Moves by the currently selected active traffic window. |
| **Timeline scrubber** | Seeks to any point in the capture. |
| **Speed** | Replays the capture faster than real time. |
| **Window** | Sets how much traffic is considered active at once. |
| **View** | Switches between grid, finding-focus, and logical-group map layouts. |
| **Focus host** | Selects the host to center in Finding Focus view. |
| **Max hosts** | Limits displayed hosts for dense captures. |
| **Host spacing** | Increases or decreases map spacing. |
| **Theme** | Switches between Cyber, Dark, and Light displays. |
| **Mark Device of Interest** | Marks or unmarks the selected/focused host for findings and final reports. |
| **Exclude Selected** | Hides the selected/focused host from the map without modifying the capture. |
| **Add Finding** | Queues the current view and timestamp as a finding entry. |
| **Final Export Report** | Builds the aggregated Word-compatible findings report. |
| **Save SVG / Save PNG** | Downloads the current map snapshot. |
| **Zoom / pan controls** | Zooms, pans, resets, or fits the network map. |
| **Reset device positions** | Clears manually dragged device locations. |

---

## 🔎 Search and filtering

Use the filter panel to search the capture without leaving the visualization.

| Filter | Examples | Notes |
| ------ | -------- | ----- |
| **Any decoded text** | `google`, `NXDOMAIN`, `TLS`, `query` | Searches decoded packet details and flow text. |
| **Any host / DNS name** | `10.10.10.4`, `.local`, `printer`, `googleapis` | Matches source or destination host data. |
| **Source host** | `192.168.1.10`, `workstation` | Matches only packet sources. |
| **Destination host** | `8.8.8.8`, `api.example.com` | Matches only packet destinations. |
| **Ports** | `53`, `80,443`, `8000-9000` | Supports single ports, comma-separated lists, and ranges. |
| **Protocol / service chips** | `TCP`, `UDP`, `DNS`, `MDNS`, `LLMNR`, `HTTPS`, `QUIC` | Click chips to quickly narrow the replay. |

Use **Previous match** and **Next match** to jump through matching traffic.

---

## 🚫 Map exclusions and cleanup

Use **Exclude Selected** to remove a selected device icon from the network map. Use **Network map exclusions** to paste or import host lists.

Accepted input styles include:

```text
10.10.10.4
printer.local
8.8.8.8, dns.google
00:11:22:33:44:55	workstation.local
```

The parser extracts likely IP addresses, IPv6 addresses, MAC addresses, and DNS-style names from CSV, TSV, copied spreadsheet lists, or plain text. Unrelated words are ignored. Exclusions affect only the visualization and reports; the original capture is not changed.

---

## ⭐ Devices of Interest

A selected host can be marked as a **Device of Interest** from the top-center action bar or the host detail panel.

Marked devices are:

- Highlighted on the map
- Included in the focus-host selector
- Included in queued findings
- Included in the final CompSec Direct report

---

## 📝 Findings and reporting

The findings workflow is intentionally cumulative:

1. Navigate to an interesting timestamp and map view.
2. Mark Devices of Interest.
3. Click **Add Finding**.
4. Enter a label and case notes.
5. The current timestamp, absolute capture time, view mode, focus host, filters, map PNG, notes, and Devices of Interest are added to the findings queue.
6. Repeat as needed.
7. Click **Final Export Report** to generate a single Word-compatible `.docx` report.

The final report includes **CompSec Direct** branding, all queued findings, all finding screenshots, case notes, timestamps, view modes, filters, and Devices of Interest.

---


## 🧠 DNS resolution

The app can label hosts using names found inside the capture, including:

- 🌐 DNS queries and responses
- 📣 mDNS traffic
- 🧭 LLMNR traffic
- 📚 PCAPNG Name Resolution Blocks

DNS labels are derived from capture contents. The app does not perform live reverse DNS, WHOIS, GeoIP, or enrichment lookups.

---

## 🔒 Privacy and security

- Capture parsing runs locally in your browser.
- PCAP/PCAPNG files are not uploaded by the app.
- Map exclusions and findings do not modify the original capture file.

---

## 📤 Supported exports

| Export | Output |
| ------ | ------ |
| **Save SVG** | Current network map as `.svg`. |
| **Save PNG** | Current network map as `.png`. |
| **Add Finding** | Adds the current view to the report queue. |
| **Final Export Report** | Builds one CompSec Direct branded `.docx` report from all queued findings. |

---

## 🧩 Supported captures

- PCAPNG Section Header, Interface Description, Enhanced Packet, Simple Packet, Name Resolution, and Interface Statistics blocks
- Classic PCAP
- Ethernet, raw IPv4/IPv6, and Linux cooked captures
- IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6, IGMP, VLAN-tagged Ethernet
- DNS, mDNS, and LLMNR packet extraction

---

## 🤝 Contributing ideas

- Add more device-type heuristics
- Add subnet-aware local grouping
- Add report templates for different incident types
- Add timeline bookmarks
- Add larger capture indexing for very large cases

---

## 🧪 v7 Updates

This version adds analyst-driven map routing, feed-based enrichment, recording, and faster report capture.

### Movable network activity lines

- Drag any visible network activity line or its small handle to reroute the curved connection.
- Manual line routing persists while the PCAP plays, pauses, rewinds, or fast-forwards.
- Routed lines are stored in the encrypted local vault after the vault is unlocked.

### Right-click actions for filters and reports

Right-click a device, connection line, label, or empty map area to open the custom map action menu.

Common actions include:

- Add host to the Any Host filter.
- Add host to Source or Destination filters.
- Add a connection's port to the Port filter.
- Add a connection's protocol/service to protocol filters.
- Mark or unmark a Device of Interest.
- Exclude a host from the map.
- Add the selected host, flow, or entire displayed map to the report queue as a PNG finding.

### Movie recording

Use **Record Movie** to record the network diagram while playback runs.

- The app requests MP4 recording first when the browser supports it.
- Browsers that do not support MP4 MediaRecorder output automatically fall back to WebM.
- The recording captures the rendered network diagram, including manual node positions, routed lines, labels, and threat markers.

### ipstack security flags

The ipstack enrichment now reads the `security` object when present and displays:

- Threat level
- Tor flag
- Proxy flag
- Proxy type
- Threat type details when returned by the subscription tier

Security flags are reflected on the network map with highlighted device outlines and warning badges.

### abuse.ch ThreatFox and MalwareBazaar enrichment

The encrypted vault can now store an **abuse.ch Auth-Key**. Use **Lookup abuse.ch Intel** to query deduplicated public IP and DNS indicators from the capture.

The lookup workflow:

1. Extracts public IPv4 addresses and related DNS names from the loaded/filtered capture.
2. Deduplicates all indicators before making API requests.
3. Posts browser-side requests to ThreatFox and MalwareBazaar using the stored `Auth-Key` header.
4. Caches results in the encrypted browser vault.
5. Marks matching devices on the network map.
6. Automatically queues matching records as **3rd party network information** findings.

### Third-party information findings

Feed matches are visible in the Findings queue before export. Final report export includes these entries alongside manually queued screenshot findings.

### Host spacing behavior

Host spacing now expands the actual layout canvas instead of increasing node shape thickness. If the diagram becomes larger than the viewport, use wheel zoom, Fit View, or pan controls to navigate the larger map.

### More legible network labels

Connection labels now use larger bold text, stronger backplates, higher contrast, and port/service details on the highest-value visible flows.
