# Network Maps

Turn scan and packet-capture data into clean, reviewable network diagrams and traffic visualizations for DFIR, incident response, asset discovery, and reporting.

This folder contains three tools:

| Tool | Input | Output | Best for |
| --- | --- | --- | --- |
| `nmap-to-drawio.py` | Nmap output (`-oN`, `-oG`, or `-oX`) | `.drawio` diagram | Converting active scan results into a quick network map |
| `pcap-to-drawio.py` | `.pcap` / `.pcapng` | Multi-page `.drawio` diagram | Turning observed traffic into host and peer communication maps |
| `pcap-visualizer.html` | `.pcap` / `.pcapng` | Local browser-based animated SVG replay | Replaying capture activity over time and filtering traffic interactively |

---

## Tools at a glance

### `nmap-to-drawio.py`

Converts Nmap scan output into a diagrams.net / draw.io network diagram.

Use this when you have active scan results and want a fast visual inventory of discovered hosts, services, and likely device types.

Highlights:

- Supports Nmap normal, grepable, and XML output.
- Creates a `.drawio` file with a central network node and host nodes laid out in a readable grid.
- Adds hover tooltips with open ports, detected services, and OS information when XML OS detection is available.
- Uses built-in draw.io shapes for inferred device types such as routers, servers, workstations, printers, phones, cameras, firewalls, and unknown devices.
- Requires only the Python standard library.

Example:

```bash
nmap -PS -sT -sV -T5 -O --open -oA scan <targets>
python nmap-to-drawio.py scan.xml network.drawio
```

Useful options:

```text
--page-name PAGE      Draw.io page name
--no-edges            Do not add the central Network node or edges
--sort {none,ip,name} Optional host sort order
```

---

### `pcap-to-drawio.py`

Converts packet captures into a multi-page diagrams.net / draw.io file.

Use this when you want to document what actually communicated in a capture, not what a scanner found.

Highlights:

- Supports `.pcap` and `.pcapng` input.
- Builds an observed host inventory from real source and destination IPs seen in the capture.
- Adds best-effort hostname enrichment from DNS, DHCP hostnames, HTTP `Host:` headers, and TLS SNI.
- Infers hosted services from observed TCP and UDP behavior.
- Creates an Overview page showing top talkers, one detail page per host, and an optional Other Hosts page for remaining systems.
- Adds directional traffic edges and hover tooltips with traffic summaries, peers, services, MAC addresses, and byte counts where available.

Requirements:

```bash
pip install dpkt
```

Example:

```bash
python3 pcap-to-drawio.py capture.pcapng output.drawio
# or
python3 pcap-to-drawio.py capture.pcap output.drawio
```

Useful options:

```text
--max-overview-hosts N   Top N hosts to show on Overview, default 200
--max-label-ports N      Max ports shown in host label, default 6
--max-peer-lines N       Max peer lines in host tooltip, 0 = all
--show-client-ports      Include inferred client/attempted ports in labels/tooltips
```

Important: PCAP-based service inference is passive. A port shown in the diagram means the capture contained traffic consistent with that service; it does not prove the port is currently open.

---

### `pcap-visualizer.html`

A standalone browser app that replays packet captures as an accelerated network traffic movie.

Use this when you want to inspect packet activity over time, search for interesting traffic, or export an SVG snapshot for notes and reports.

Highlights:

- Runs locally in a modern browser; no server, install, package manager, or external JavaScript libraries required.
- Replays captures with play, pause, rewind, fast-forward, scrub, speed, and active-window controls.
- Shows a persistent host graph with stable grid layout, active-host highlighting, directed traffic edges, and animated packet transitions.
- Supports search and filters for hosts, DNS names, source, destination, ports, protocols, services, and decoded packet text.
- Labels hosts using DNS, mDNS, LLMNR, and PCAPNG name-resolution data found inside the capture.
- Exports the current network view as an SVG snapshot.
- Parses captures locally in the browser and does not upload files or call external enrichment services.

Example:

```text
Open pcap-visualizer.html in your browser.
Drag a .pcapng or .pcap file into the page, or click Open capture.
Use the playback, filter, and export controls to review traffic.
```

Optional local web server workflow:

```bash
python3 -m http.server 8000
```

Then browse to:

```text
http://localhost:8000/pcap-visualizer.html
```

---

## Choosing the right tool

| Scenario | Recommended tool |
| --- | --- |
| You ran Nmap and want a visual host/service map | `nmap-to-drawio.py` |
| You have a capture and want a static communication map | `pcap-to-drawio.py` |
| You want to replay traffic over time and filter interactively | `pcap-visualizer.html` |
| You need a diagram for a report | `nmap-to-drawio.py` or `pcap-to-drawio.py` |
| You need a snapshot of a specific traffic moment | `pcap-visualizer.html` |

---

## Opening `.drawio` output

Open generated `.drawio` files with diagrams.net:

- Online: <https://app.diagrams.net/>
- Desktop: diagrams.net / draw.io desktop app

Then use **File → Open from Device** and select the generated `.drawio` file.

---

## Privacy and security notes

- `nmap-to-drawio.py` and `pcap-to-drawio.py` run locally where you execute them.
- `pcap-visualizer.html` parses captures locally in your browser.
- The visualizer does not upload captures and does not call external DNS, WHOIS, GeoIP, or enrichment APIs.
- For sensitive captures, use the tools offline or inside an isolated analysis environment.

---

## Requirements summary

| Tool | Requirements |
| --- | --- |
| `nmap-to-drawio.py` | Python 3.13+; standard library only |
| `pcap-to-drawio.py` | Python 3.12+; `dpkt` |
| `pcap-visualizer.html` | Modern desktop browser; no install required |

---

## Contributing ideas

Pull requests and ideas are welcome. Good areas to improve:

- Device and service inference heuristics
- Additional packet-capture link-layer decoders
- Smarter layouts and clustering for large networks
- Optional filtering and export formats
- Subnet grouping, host pinning, zoom, and richer protocol panels
