# 🗺️ Network Maps: nmap to drawio

Turn **Nmap scans** into clean, readable **diagrams.net / draw.io** network diagrams — automatically. ✨

[![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)](#requirements)
[![Output](https://img.shields.io/badge/Output-.drawio-orange?logo=diagramsdotnet&logoColor=white)](#opening-the-diagram)
[![Nmap](https://img.shields.io/badge/Input-Nmap-4CAF50?logo=gnometerminal&logoColor=white)](#usage)

---

## 🚀 What it does

✅ Converts Nmap output into a `.drawio` diagram with:

- 🕸️ **Network hub** at the top + hosts laid out in a **left-to-right grid**
- 🧠 **OS identification** (from `-oX` + `-O`) shown in tooltips
- 🧷 **Hover tooltips** showing open ports per host
- 🧩 **Device shapes/icons** from built-in draw.io libraries (MSCAE/Cisco/AWS/iOS7)
- 🧱 “**To Front**” rendering so device shapes are always above network links
- 🏷️ Embedded **branding banner** (logo + text) inside the Python file (no external assets)

---

## ✨ Preview (what you’ll get)

- 🟠 A **Network** icon at the top
- 🔷 Hosts arranged evenly to avoid clutter
- 🖱️ Hover any node to see ports/services (and OS when available)  \

### Simple Network
![](https://github.com/compsecdirect/dfir/blob/main/network-maps/nmap-to-drawio/nmap_small_office.xml.png)
### Medium Network
![](https://github.com/compsecdirect/dfir/blob/main/network-maps/nmap-to-drawio/nmap_medium_corp_300.xmL.png)
---

## 📦 Requirements

- 🐍 Python **3.13+**
- ✅ No external dependencies (stdlib only)

---

## 🛠️ Installation

```bash
git clone https://github.com/compsecdirect/dfir.git
cd network-maps
python nmap-to-drawio.py --help

nmap -PS -sT -sV -T5 -O --open -oA scan <targets>
python nmap-to-drawio.py scan.xml network.drawio
```
## 🧰 CLI Options
```
positional arguments:
  input                 Nmap output file (-oN/-oG/-oX), or '-' for stdin
  output                Output .drawio file path

optional arguments:
  --page-name PAGE      Draw.io page name (default: Page-1)
  --no-edges            Do not add the central Network node or edges
  --sort {none,ip,name} Optional host sort order
```

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
| ❓ unknown      | `mxgraph.mscae.enterprise.device`             |

### Heuristics use:

🧬 OS guess (XML -O)

🔍 Common ports/services (RDP/SMB/RTSP/SIP/IPP, etc.)  

## 🧷 Tooltips

Hover over a host node to see:

🧠 OS guess + accuracy (when available)  
🔓 Open ports and detected services/versions

Tooltips are implemented via HTML labels (title="...").

## 🤝 Contributing

PRs welcome! 💚

Ideas:

🧠 Improve device heuristics

🧩 Add more shape mappings

📐 Smarter layouts for huge scans
