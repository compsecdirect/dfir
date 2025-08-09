# Kleared4 ROCKY EVTX Log Visualizer

R.O.C.K.Y. – Rapid Observation & Correlation Kit for Windows Events  

A lightweight web-based tool that visualizes **Windows Event Logs** from the System and Security logs. This project helps **incident responders** identify potentially malicious activity using interactive charts and searchable log tables.

R – Rapid (Emphasizes speed in processing logs)

O – Observation (Focus on visibility and monitoring)

C – Correlation (Links related events together for better incident context)

K – Knowledge (Uses known patterns and MITRE ATT&CK mappings)

Y – Yes (Does all the above)

---

## 🔧 Features

- 📊 Visual charts for Event ID frequency and Event Levels
  - Chart.js to jQuery Filter Label matches
- 🔎 Searchable, sortable table of raw log entries
  - Highlight suspicious Event IDs (e.g., 4625, 4688, 4672)
  - Export filtered logs to CSV
  - Annotate events with MITRE ATT&CK mappings
- 📁 Portable – runs locally with no server installation
- 💻 Runs using PowerShell and Python as a simple web server (optional)

---

## 🛠 Setup Instructions

### 1. **Log Collection (Admin Privileges Required)**
Run the PowerShell script to collect logs:

```powershell
.\collect.ps1
```

This will:
- Export the last 1000 events from the **System** and **Security** logs
- Save them into `log_data.json`
- Optionally start a web server if you have Python in your PATH

If you're an **admin** and don't want Python in your environment, you can only run the collection step. Then pass the folder to a **non-admin user** to serve it.

---

### 2. **Launching the Web Interface (Regular User)**
You can run a local server using Python (must be installed):

```powershell
.\serve.ps1
```

Then open your browser to:
```
http://localhost:8000
```

---

## 📂 Files

- `index.html` – Main web UI with jQuery and chart.js
- `main.js` – Logic for charting and table population
- `style.css` – Styling with Tailwind + dark theme
- `log_data.json` – Output of log collection
- `collect.ps1` – PowerShell script to extract logs
- `serve.ps1` – PowerShell script to serve the app with python

---

## ⚠️ Notes

- Execution policy may need to be relaxed for the script to run:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```
- Ensure `python` is installed for the web server method, or modify `serve.ps1` to use a native PowerShell server

* Uses optimistic logging; meaning that some of the useful EventID's and Mitre Attack mapping require the host to already collect non-default logs. 
  - Firewall Logs  
  - Object Access (SACL) 
  - File Shares 
---

## 🧩 Future Ideas
- Grouped Event ID's
- Pre-Parser for json data

---

Built for defenders. Fast. Local. Insightful. 🔍

