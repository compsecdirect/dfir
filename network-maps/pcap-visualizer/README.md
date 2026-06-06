# 🎞️ PCAP Visualizer

Replay packet captures as an accelerated **network traffic movie** — with persistent hosts, DNS labels, searchable traffic, and an Etterape-style live SVG diagram. ✨

[![App](https://img.shields.io/badge/App-Standalone%20HTML-38BDF8?logo=html5&logoColor=white)](#requirements)
[![Input](https://img.shields.io/badge/Input-PCAPNG%20%2F%20PCAP-4CAF50?logo=wireshark&logoColor=white)](#supported-captures)
[![Visualization](https://img.shields.io/badge/View-Animated%20SVG-A78BFA?logo=svg&logoColor=white)](#visualization-model)
[![Privacy](https://img.shields.io/badge/Privacy-Local%20Only-34D399?logo=firefoxbrowser&logoColor=white)](#privacy-and-security)

---

## 🚀 What it does

✅ Turns packet capture files into an interactive live network replay with:

- 🕸️ **Persistent host graph** where hosts remain visible after they first appear
- 📐 **Left-to-right, top-to-bottom layout** to avoid the bouncing force-graph effect
- ↔️ **Adjustable host spacing** to reduce clutter on dense captures
- 🧭 **Play, pause, rewind, fast-forward, scrub, and speed controls**
- ✨ **Animated packet transitions** between communicating hosts
- 🧠 **DNS, mDNS, LLMNR, and PCAPNG name-resolution labels** when available
- 🔎 **Search and filters** for hosts, DNS names, source, destination, ports, protocols, services, and decoded packet text
- 📊 **Current-window stats**, top flows, packet hits, protocol counts, DNS resolutions, and selected-host details
- 🖼️ **SVG snapshot export** for documenting interesting traffic moments
- 🔒 **Local-only parsing** in the browser; captures are not uploaded

---

## ✨ Preview (what you’ll get)

- 🔷 Hosts arranged in a stable grid instead of bouncing around
- 🟢 Active hosts highlighted for the current playback window
- ⚪ Inactive-but-discovered hosts retained on the diagram
- ➡️ Directed traffic edges showing who is talking to whom
- ✨ Moving particles showing packet transitions as the capture plays
- 🏷️ DNS labels shown above IP addresses when names are decoded
- 🔍 Filtered packet hit table for traffic of interest

---

## 📦 Requirements

- 🌐 A modern desktop browser: Chrome, Edge, Firefox, Safari, or equivalent
- 📁 A `.pcapng` or classic `.pcap` file
- ✅ No server required
- ✅ No install required
- ✅ No external JavaScript libraries or package manager required

> For very large captures, a browser with more available memory will perform better.

---

## 🛠️ Installation

Download or copy the application files into a folder:

```text
pcap-visualizer
├── pcap-visualizer.html
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
4. Adjust **Speed**, **Window**, **Max hosts**, and **Host spacing** as needed.
5. Use DNS, host, port, and protocol filters to focus on interesting traffic.
6. Click a host node to view host details and known DNS aliases.
7. Use **Save SVG** to export the current network view.

---

## 🎛️ Controls

| Control | What it does |
| ------- | ------------ |
| **Play / Pause** | Starts or pauses timestamp-based replay |
| **-10s / +10s** | Jumps backward or forward ten seconds |
| **-1 window / +1 window** | Moves by the currently selected active traffic window |
| **Timeline scrubber** | Seeks to any point in the capture |
| **Speed** | Replays the capture faster than real time |
| **Window** | Sets how much traffic is considered active at once, such as 1, 2, 5, 10, or 30 seconds |
| **Max hosts** | Limits the number of displayed hosts for dense captures |
| **Host spacing** | Increases or decreases grid spacing between hosts |
| **Keep discovered hosts visible** | Keeps hosts on the diagram after they first appear |
| **Prefer DNS labels** | Shows decoded names instead of only IP addresses |
| **Show IP under DNS label** | Displays the raw address beneath a DNS name |
| **Reset view** | Clears transient particles and recomputes layout |
| **Save SVG** | Downloads the current diagram as an SVG snapshot |

---

## 🔎 Search and filtering

Use the filter panel to search the capture without leaving the visualization.

| Filter | Examples | Notes |
| ------ | -------- | ----- |
| **Any decoded text** | `google`, `NXDOMAIN`, `TLS`, `query` | Searches decoded packet details and flow text |
| **Any host / DNS name** | `10.10.10.4`, `.local`, `printer`, `googleapis` | Matches source or destination host data |
| **Source host** | `192.168.1.10`, `workstation` | Matches only packet sources |
| **Destination host** | `8.8.8.8`, `api.example.com` | Matches only packet destinations |
| **Ports** | `53`, `80,443`, `8000-9000` | Supports single ports, comma-separated lists, and ranges |
| **Protocol / service chips** | `TCP`, `UDP`, `DNS`, `MDNS`, `LLMNR`, `HTTPS`, `QUIC` | Click chips to quickly narrow the replay |

Use **Previous match** and **Next match** to jump through matching traffic.

---

## 🧠 DNS resolution

The app can label hosts using names found inside the capture, including:

- 🌐 DNS queries and responses
- 📣 mDNS traffic
- 🧭 LLMNR traffic
- 📚 PCAPNG Name Resolution Blocks

DNS labels are derived only from capture contents. The app does not perform live reverse DNS lookups and does not send IP addresses to outside services.

---

## 🧭 Visualization model

The graph is designed for readable traffic review rather than physical network topology discovery.

- Hosts are placed in a **stable grid** from left to right, top to bottom.
- Hosts appear when first discovered in the replay timeline.
- Previously discovered hosts remain visible when **Keep discovered hosts visible** is enabled.
- Hosts active in the current time window are brighter.
- Hosts not active in the current time window are faded.
- Edges represent traffic observed in the current playback window.
- Packet particles animate from source to destination as traffic crosses the current timestamp.
- Node size reflects activity and total observed packets.

---

## 📡 Supported captures

| Area | Support |
| ---- | ------- |
| **File formats** | PCAPNG and classic PCAP |
| **PCAPNG blocks** | Section Header, Interface Description, Enhanced Packet, Name Resolution, Interface Statistics |
| **Timestamp handling** | Uses packet timestamps and interface timestamp resolution to replay traffic in capture time |
| **Link-layer decoding** | Ethernet, raw IP, Linux cooked capture, VLAN-tagged Ethernet |
| **Network protocols** | IPv4, IPv6, ARP |
| **Transport / control** | TCP, UDP, ICMP, ICMPv6, IGMP |
| **Name protocols** | DNS, mDNS, LLMNR |
| **Service labeling** | Common service labels such as DNS, HTTPS, QUIC, mDNS, and LLMNR when ports or decoded traffic indicate them |

Unsupported or malformed packets are skipped rather than stopping the entire parse.

---

## 🧷 Host details and tooltips

Click a host node to show:

- Display label
- Raw address
- Host class
- Current-window packet count
- Total packet count
- Total byte count
- Known DNS aliases
- One-click host filtering

Hover over edges and nodes to see packet and flow summaries.

---

## 🖼️ Exporting

Use **Save SVG** to export the current network diagram.

This is useful for:

- Incident notes
- Timeline reports
- Screenshots without browser UI
- Sharing a specific capture moment with teammates

---

## 🔐 Privacy and security

- Capture parsing runs locally in your browser.
- The file is read from disk into browser memory.
- The app does not upload captures.
- The app does not call external DNS, WHOIS, GeoIP, or enrichment APIs.
- DNS names shown in the interface are decoded from the capture itself.

For sensitive captures, use the tool offline or in an isolated browser profile.

---

## ⚠️ Known limitations

- Encrypted DNS, encrypted SNI, VPN tunnels, and opaque application payloads may hide useful hostnames.
- The app does not decrypt TLS or reconstruct full application sessions.
- DNS names only appear if the capture contains DNS, mDNS, LLMNR, or PCAPNG name-resolution data.
- Very large captures can consume significant browser memory.
- Dense captures may still need filtering, lower **Max hosts**, or increased **Host spacing**.
- The diagram shows observed communication, not guaranteed physical topology.

---

## 🧩 Troubleshooting

### The graph is too crowded

Try:

- Increase **Host spacing**
- Lower **Max hosts**
- Filter by host, port, or protocol
- Use a smaller playback **Window**

### I only see IP addresses

The capture may not contain DNS answers or name-resolution records. Enable **Prefer DNS labels** and **Show IP under DNS label**, then check the DNS panel for decoded names.

### Playback feels slow

Try:

- Lower **Max hosts**
- Use a shorter **Window**
- Filter to specific hosts or ports
- Close other memory-heavy browser tabs

### Some packets are missing from the graph

Packets with unsupported link types, malformed headers, or insufficient decoded source/destination information may be skipped for visualization.

---

## 🧪 Development notes

The application is intentionally built as a single standalone HTML file:

```text
pcap-visualizer.html
```

Internally it uses:

- Browser `File` APIs to load captures
- A Web Worker to parse capture data without freezing the UI
- JavaScript `DataView` parsing for PCAPNG and PCAP structures
- SVG for the network diagram, edges, nodes, labels, and packet particles
- In-memory indexes for filters, DNS labels, host stats, and playback windows

---

## 🗺️ Roadmap ideas

Ideas for future improvements:

- 🔍 Zoom and pan controls
- 📦 Subnet grouping or collapsible host groups
- 📌 Pinning important hosts
- 🚦 Separate lanes for internal, external, multicast, and broadcast hosts
- 🧊 Collapse low-activity hosts
- 📁 Export filtered packet summaries as CSV or JSON
- 🕵️ Optional protocol-specific panels for DNS, HTTP, TLS, and SMB metadata

---

## 🤝 Contributing

PRs and ideas are welcome. 💚

Good next contributions:

- Improve service labeling heuristics
- Add more link-layer decoders
- Add subnet grouping
- Improve performance for very large captures
- Add richer export formats
