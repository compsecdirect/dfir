(() => {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const els = {
    fileInput: document.getElementById('fileInput'),
    fileName: document.getElementById('fileName'),
    playPause: document.getElementById('playPause'),
    back10: document.getElementById('back10'),
    backStep: document.getElementById('backStep'),
    forwardStep: document.getElementById('forwardStep'),
    forward10: document.getElementById('forward10'),
    prevMatch: document.getElementById('prevMatch'),
    nextMatch: document.getElementById('nextMatch'),
    speedSelect: document.getElementById('speedSelect'),
    windowSelect: document.getElementById('windowSelect'),
    themeSelect: document.getElementById('themeSelect'),
    maxNodes: document.getElementById('maxNodes'),
    maxNodesLabel: document.getElementById('maxNodesLabel'),
    hostSpacing: document.getElementById('hostSpacing'),
    hostSpacingLabel: document.getElementById('hostSpacingLabel'),
    showAll: document.getElementById('showAll'),
    preferDns: document.getElementById('preferDns'),
    showIpUnderName: document.getElementById('showIpUnderName'),
    timeline: document.getElementById('timeline'),
    currentTime: document.getElementById('currentTime'),
    durationTime: document.getElementById('durationTime'),
    snapshot: document.getElementById('snapshot'),
    savePng: document.getElementById('savePng'),
    exportFindings: document.getElementById('exportFindings'),
    resetView: document.getElementById('resetView'),
    fps: document.getElementById('fps'),
    searchText: document.getElementById('searchText'),
    hostFilter: document.getElementById('hostFilter'),
    srcFilter: document.getElementById('srcFilter'),
    dstFilter: document.getElementById('dstFilter'),
    portFilter: document.getElementById('portFilter'),
    protocolChips: document.getElementById('protocolChips'),
    clearFilters: document.getElementById('clearFilters'),
    filterStatus: document.getElementById('filterStatus'),
    graphShell: document.getElementById('graphShell'),
    graphSvg: document.getElementById('graphSvg'),
    gridLayer: document.getElementById('gridLayer'),
    edgesLayer: document.getElementById('edgesLayer'),
    particlesLayer: document.getElementById('particlesLayer'),
    nodesLayer: document.getElementById('nodesLayer'),
    zoomIn: document.getElementById('zoomIn'),
    zoomOut: document.getElementById('zoomOut'),
    zoomReset: document.getElementById('zoomReset'),
    zoomFit: document.getElementById('zoomFit'),
    panUp: document.getElementById('panUp'),
    panDown: document.getElementById('panDown'),
    panLeft: document.getElementById('panLeft'),
    panRight: document.getElementById('panRight'),
    emptyOverlay: document.getElementById('emptyOverlay'),
    progressOverlay: document.getElementById('progressOverlay'),
    progressText: document.getElementById('progressText'),
    progressFill: document.getElementById('progressFill'),
    windowRange: document.getElementById('windowRange'),
    windowPackets: document.getElementById('windowPackets'),
    windowHosts: document.getElementById('windowHosts'),
    windowBytes: document.getElementById('windowBytes'),
    windowEdges: document.getElementById('windowEdges'),
    summaryPanel: document.getElementById('summaryPanel'),
    dnsPanel: document.getElementById('dnsPanel'),
    protocolLegend: document.getElementById('protocolLegend'),
    topFlows: document.getElementById('topFlows'),
    packetHits: document.getElementById('packetHits'),
    hostPanel: document.getElementById('hostPanel'),
    findingsModal: document.getElementById('findingsModal'),
    findingsForm: document.getElementById('findingsForm'),
    findingLabel: document.getElementById('findingLabel'),
    findingNotes: document.getElementById('findingNotes'),
    cancelFindings: document.getElementById('cancelFindings'),
    devicesOfInterestList: document.getElementById('devicesOfInterestList'),
    status: document.getElementById('status')
  };

  const state = {
    worker: null,
    workerUrl: null,
    capture: null,
    packets: [],
    filteredPackets: [],
    filteredHostStats: [],
    summary: null,
    dns: null,
    hostIndex: new Map(),
    selectedProtocols: new Set(),
    filters: null,
    playing: false,
    speed: 30,
    currentTime: 0,
    previousTime: 0,
    duration: 0,
    windowSec: 1,
    theme: 'cyber',
    maxNodes: 160,
    hostSpacing: 1.45,
    showAll: true,
    preferDns: true,
    showIpUnderName: true,
    selectedHost: null,
    devicesOfInterest: new Set(),
    panZoom: { x: 0, y: 0, scale: 1 },
    isPanning: false,
    panStart: null,
    particles: [],
    dimensions: { w: 900, h: 640 },
    lastFrameAt: 0,
    fpsFrames: 0,
    fpsStarted: performance.now(),
    lastPanelAt: 0,
    layoutKey: '',
    layout: new Map(),
    hostSlots: new Map(),
    hostOrder: [],
    lastView: null,
    needsRender: true,
    filterDebounce: 0
  };

  function fmtCount(n) {
    return new Intl.NumberFormat().format(Math.round(Number(n) || 0));
  }

  function fmtBytes(bytes) {
    bytes = Number(bytes || 0);
    if (bytes < 1024) return bytes + ' B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    let v = bytes / 1024;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return (v >= 10 ? v.toFixed(1) : v.toFixed(2)) + ' ' + units[i];
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds)) return '00:00.000';
    const sign = seconds < 0 ? '-' : '';
    seconds = Math.abs(seconds);
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    const ms = Math.floor((seconds - Math.floor(seconds)) * 1000);
    const tail = String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0') + '.' + String(ms).padStart(3, '0');
    return sign + (h ? h + ':' + tail : tail);
  }

  function formatAbsTimestamp(ts) {
    if (!Number.isFinite(ts)) return '--';
    try { return new Date(ts * 1000).toLocaleString(undefined, { hour12: false }); }
    catch { return String(ts); }
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function escapeAttr(value) { return escapeHtml(value).replace(/`/g, '&#096;'); }

  function shortenHost(host, max = 26) {
    host = String(host || '');
    if (host.length <= max) return host;
    if (host.includes(':') && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(host)) {
      const parts = host.split(':');
      if (parts.length > 4) return parts[0] + ':' + parts[1] + ':...:' + parts[parts.length - 1];
    }
    const left = Math.max(6, Math.floor(max * 0.45));
    const right = Math.max(5, max - left - 3);
    return host.slice(0, left) + '...' + host.slice(-right);
  }

  function hashString(s) {
    s = String(s || '');
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  function protocolClass(protocolOrService) {
    const p = String(protocolOrService || '').toLowerCase();
    if (p.includes('tcp') || p.includes('http') || p.includes('https') || p.includes('quic')) return 'tcp';
    if (p.includes('udp') || p.includes('dns') || p.includes('mdns') || p.includes('llmnr') || p.includes('dhcp') || p.includes('ntp')) return 'udp';
    if (p.includes('arp')) return 'arp';
    if (p.includes('icmp') || p.includes('igmp')) return 'icmp';
    return 'other';
  }

  function classifyHost(host) {
    const meta = state.hostIndex.get(host);
    if (meta && meta.className) return meta.className;
    if (!host) return 'remote';
    if (host === '255.255.255.255' || String(host).toLowerCase() === 'ff:ff:ff:ff:ff:ff') return 'broadcast';
    if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(host)) {
      const first = parseInt(host.slice(0, 2), 16);
      return (first & 1) ? 'multicast' : 'mac';
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      const p = host.split('.').map(Number);
      if (p[0] >= 224 && p[0] <= 239) return 'multicast';
      if (p[0] === 10 || p[0] === 127 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254)) return 'local';
      return 'remote';
    }
    const h = String(host).toLowerCase();
    if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return 'local';
    if (h.startsWith('ff')) return 'multicast';
    return 'remote';
  }

  function hostLabel(host) {
    const meta = state.hostIndex.get(host);
    if (state.preferDns && meta && meta.label && meta.label !== host) return meta.label;
    return host;
  }

  function hostDisplay(host, withIp = true) {
    const label = hostLabel(host);
    if (withIp && state.preferDns && state.showIpUnderName && label !== host) return label + ' (' + host + ')';
    return label;
  }

  function hostSearchText(host) {
    const meta = state.hostIndex.get(host);
    const parts = [host];
    if (meta) parts.push(meta.label, ...(meta.names || []));
    return parts.filter(Boolean).join(' ').toLowerCase();
  }


  function cssVar(name, fallback = '') {
    try {
      const value = getComputedStyle(document.body).getPropertyValue(name).trim();
      return value || fallback;
    } catch { return fallback; }
  }

  function escapeXml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  function slugify(value, fallback = 'finding') {
    const s = String(value || '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
    return s || fallback;
  }

  function applyTheme(theme) {
    state.theme = theme || 'cyber';
    document.body.setAttribute('data-theme', state.theme);
    if (els.themeSelect) els.themeSelect.value = state.theme;
    state.needsRender = true;
  }

  function setPanZoom(next) {
    state.panZoom.scale = Math.max(0.25, Math.min(5, Number(next.scale ?? state.panZoom.scale) || 1));
    state.panZoom.x = Number(next.x ?? state.panZoom.x) || 0;
    state.panZoom.y = Number(next.y ?? state.panZoom.y) || 0;
    applyGraphTransform();
  }

  function applyGraphTransform() {
    const t = 'translate(' + state.panZoom.x.toFixed(2) + ' ' + state.panZoom.y.toFixed(2) + ') scale(' + state.panZoom.scale.toFixed(4) + ')';
    for (const layer of [els.gridLayer, els.edgesLayer, els.particlesLayer, els.nodesLayer]) {
      if (layer) layer.setAttribute('transform', t);
    }
  }

  function zoomGraph(factor, center) {
    const rect = els.graphSvg.getBoundingClientRect();
    const cx = center && Number.isFinite(center.x) ? center.x : rect.width / 2;
    const cy = center && Number.isFinite(center.y) ? center.y : rect.height / 2;
    const oldScale = state.panZoom.scale;
    const newScale = Math.max(0.25, Math.min(5, oldScale * factor));
    const worldX = (cx - state.panZoom.x) / oldScale;
    const worldY = (cy - state.panZoom.y) / oldScale;
    setPanZoom({ scale: newScale, x: cx - worldX * newScale, y: cy - worldY * newScale });
  }

  function panGraph(dx, dy) {
    setPanZoom({ x: state.panZoom.x + dx, y: state.panZoom.y + dy, scale: state.panZoom.scale });
  }

  function resetPanZoom() {
    setPanZoom({ x: 0, y: 0, scale: 1 });
  }

  function fitVisibleGraph() {
    const values = Array.from(state.layout.values());
    if (!values.length) return resetPanZoom();
    const w = state.dimensions.w;
    const h = state.dimensions.h;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const p of values) {
      minX = Math.min(minX, p.x - p.r - 72);
      minY = Math.min(minY, p.y - p.r - 72);
      maxX = Math.max(maxX, p.x + p.r + 72);
      maxY = Math.max(maxY, p.y + p.r + 92);
    }
    const bw = Math.max(1, maxX - minX);
    const bh = Math.max(1, maxY - minY);
    const scale = Math.max(0.25, Math.min(3.5, Math.min(w / bw, h / bh)));
    const x = (w - bw * scale) / 2 - minX * scale;
    const y = (h - bh * scale) / 2 - minY * scale;
    setPanZoom({ x, y, scale });
  }

  function classRank(className) {
    return ({ local: 0, remote: 1, mac: 2, multicast: 3, broadcast: 4, other: 5 })[className] ?? 6;
  }

  function buildHostStatsFromPackets(packets) {
    const map = new Map();
    function ensure(host, rel) {
      if (!map.has(host)) {
        const meta = state.hostIndex.get(host) || { host, label: host, names: [], className: classifyHost(host) };
        map.set(host, {
          host,
          label: meta.label || host,
          names: (meta.names || []).slice(),
          className: meta.className || classifyHost(host),
          sentPackets: 0, recvPackets: 0, sentBytes: 0, recvBytes: 0, totalPackets: 0, totalBytes: 0,
          firstSeen: rel, lastSeen: rel,
          serviceCounts: Object.assign({}, meta.serviceCounts || {}),
          protocolCounts: Object.assign({}, meta.protocolCounts || {}),
          ports: Object.assign({}, meta.ports || {})
        });
      }
      const item = map.get(host);
      if (!Number.isFinite(item.firstSeen) || rel < item.firstSeen) item.firstSeen = rel;
      if (!Number.isFinite(item.lastSeen) || rel > item.lastSeen) item.lastSeen = rel;
      return item;
    }
    function noteTraffic(item, p, direction) {
      bumpObj(item.serviceCounts, p.service || p.protocol || 'unknown', 1);
      bumpObj(item.protocolCounts, p.protocol || 'unknown', 1);
      if (direction === 'src' && Number.isFinite(p.sport)) bumpObj(item.ports, p.sport, 1);
      if (direction === 'dst' && Number.isFinite(p.dport)) bumpObj(item.ports, p.dport, 1);
      if (Number.isFinite(p.sport)) bumpObj(item.ports, p.sport, 0);
      if (Number.isFinite(p.dport)) bumpObj(item.ports, p.dport, 0);
    }
    for (const p of packets || []) {
      const s = ensure(p.src, p.rel);
      const d = ensure(p.dst, p.rel);
      s.sentPackets += 1; s.sentBytes += p.bytes || 0; s.totalPackets += 1; s.totalBytes += p.bytes || 0;
      d.recvPackets += 1; d.recvBytes += p.bytes || 0; d.totalPackets += 1; d.totalBytes += p.bytes || 0;
      noteTraffic(s, p, 'src');
      noteTraffic(d, p, 'dst');
    }
    const stats = Array.from(map.values()).sort((a, b) =>
      (Number.isFinite(a.firstSeen) ? a.firstSeen : Infinity) - (Number.isFinite(b.firstSeen) ? b.firstSeen : Infinity) ||
      b.totalPackets - a.totalPackets ||
      classRank(a.className) - classRank(b.className) ||
      a.host.localeCompare(b.host)
    );
    for (const item of stats) {
      item.deviceType = inferDeviceType(item);
      const prev = state.hostIndex.get(item.host) || {};
      state.hostIndex.set(item.host, Object.assign({}, prev, item, {
        label: item.label || prev.label || item.host,
        names: item.names && item.names.length ? item.names : (prev.names || []),
        className: item.className || prev.className || classifyHost(item.host),
        deviceType: item.deviceType || prev.deviceType || 'unknown'
      }));
    }
    return stats;
  }

  function inferDeviceType(meta) {
    const cls = meta.className || classifyHost(meta.host);
    const labelText = [meta.host, meta.label, ...(meta.names || [])].join(' ').toLowerCase();
    const services = Object.keys(meta.serviceCounts || {}).join(' ').toLowerCase();
    const ports = Object.keys(meta.ports || {}).map(Number);
    const hasPort = n => ports.includes(n);
    const hasSvc = s => services.includes(s.toLowerCase()) || labelText.includes(s.toLowerCase());
    if (cls === 'broadcast') return 'broadcast';
    if (cls === 'multicast') return 'multicast';
    if (cls === 'mac') return 'adapter';
    if (/printer|print|ipp|jetdirect/.test(labelText) || hasPort(9100) || hasPort(631) || hasSvc('IPP')) return 'printer';
    if (/router|gateway|gw|firewall|pfsense|opnsense|ubnt|unifi/.test(labelText) || hasSvc('DHCP') || hasSvc('IKE') || hasSvc('OSPF') || hasSvc('SNMP')) return 'router';
    if (/dns|resolver|domain|dc|ldap|kerberos|server|srv|nas|smb/.test(labelText) || hasSvc('DNS') || hasSvc('LDAP') || hasSvc('SMB') || hasSvc('HTTP') || hasSvc('HTTPS') || hasSvc('SSH') || hasSvc('RDP')) return 'server';
    if (cls === 'remote') return 'cloud';
    if (cls === 'local') return 'workstation';
    return 'device';
  }

  function rebuildHostSlots(stats) {
    state.hostSlots.clear();
    state.hostOrder = [];
    (stats || []).forEach((meta, index) => {
      state.hostSlots.set(meta.host, index);
      state.hostOrder.push(meta.host);
    });
  }

  function binarySearchPackets(packets, relTime) {
    let lo = 0, hi = packets.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (packets[mid].rel < relTime) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  function makeWorker() {
    if (state.worker) state.worker.terminate();
    if (state.workerUrl) URL.revokeObjectURL(state.workerUrl);
    const workerSource = document.getElementById('workerSource').textContent;
    const blob = new Blob([workerSource], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    const worker = new Worker(url);
    state.worker = worker;
    state.workerUrl = url;
    worker.onmessage = event => {
      const msg = event.data || {};
      if (msg.type === 'progress') {
        const p = msg.progress || {};
        const pct = p.size ? Math.min(100, Math.max(0, (p.offset / p.size) * 100)) : 0;
        els.progressFill.style.width = pct.toFixed(1) + '%';
        els.progressText.textContent = 'Decoded ' + fmtCount(p.packets) + ' packets while scanning ' + pct.toFixed(0) + '% of the file...';
      } else if (msg.type === 'done') {
        finishLoad(msg.name, msg.parsed);
      } else if (msg.type === 'error') {
        failLoad(msg.message || 'Unknown parser error');
      }
    };
    worker.onerror = event => failLoad(event.message || 'Worker error');
    return worker;
  }

  async function loadFile(file) {
    if (!file) return;
    resetCaptureState();
    els.fileName.textContent = file.name;
    els.emptyOverlay.classList.add('hidden');
    els.progressOverlay.classList.remove('hidden');
    els.progressFill.style.width = '0%';
    els.progressText.textContent = 'Reading ' + fmtBytes(file.size) + ' from disk...';
    els.status.textContent = 'Reading file into browser memory...';
    try {
      const buffer = await file.arrayBuffer();
      const worker = makeWorker();
      els.progressText.textContent = 'Parsing capture blocks and DNS records...';
      worker.postMessage({ type: 'parse', name: file.name, buffer }, [buffer]);
    } catch (error) {
      failLoad(error && error.stack ? error.stack : String(error));
    }
  }

  function failLoad(message) {
    els.progressOverlay.classList.add('hidden');
    els.emptyOverlay.classList.remove('hidden');
    els.status.textContent = 'Could not load capture: ' + message;
    console.error(message);
  }

  function resetCaptureState() {
    state.capture = null;
    state.packets = [];
    state.filteredPackets = [];
    state.filteredHostStats = [];
    state.summary = null;
    state.dns = null;
    state.hostIndex.clear();
    state.selectedProtocols.clear();
    state.filters = null;
    state.playing = false;
    state.currentTime = 0;
    state.previousTime = 0;
    state.duration = 0;
    state.selectedHost = null;
    state.devicesOfInterest.clear();
    resetPanZoom();
    state.particles = [];
    state.layoutKey = '';
    state.layout.clear();
    state.hostSlots.clear();
    state.hostOrder = [];
    state.lastView = null;
    updateControlsEnabled(false);
    updatePlaybackButton();
    renderSummary(null);
    renderDnsPanel(null);
    renderProtocolFilter(null);
    renderHostPanel(null, null);
    renderEmptyGraph();
    updateFilterStatus();
  }

  function finishLoad(name, parsed) {
    state.capture = parsed;
    state.packets = parsed.packets || [];
    state.filteredPackets = state.packets;
    state.summary = parsed.summary || {};
    state.dns = parsed.dns || null;
    state.duration = state.summary.duration || 0;
    state.currentTime = 0;
    state.previousTime = 0;
    state.particles = [];
    state.hostIndex.clear();
    for (const h of state.summary.hostStats || []) state.hostIndex.set(h.host, h);
    state.filteredHostStats = buildHostStatsFromPackets(state.filteredPackets);
    rebuildHostSlots(state.filteredHostStats);
    els.progressOverlay.classList.add('hidden');
    els.emptyOverlay.classList.add('hidden');
    els.fileName.textContent = name + ' - ' + fmtCount(state.summary.packetsDecoded) + ' packets - ' + formatDuration(state.duration);
    els.timeline.max = Math.max(0, state.duration).toFixed(3);
    els.timeline.value = '0';
    els.durationTime.textContent = formatDuration(state.duration);
    updateControlsEnabled(true);
    renderSummary(state.summary);
    renderDnsPanel(state.dns);
    renderProtocolFilter(state.summary);
    applyFilters(false);
    setTime(0, true);
    els.status.textContent = 'Loaded ' + fmtCount(state.summary.packetsDecoded) + ' decoded packets, ' + fmtCount(state.summary.hostCount) + ' hosts, ' + fmtCount(state.summary.dnsPacketCount) + ' DNS-family packets, ' + fmtCount(state.summary.dnsResolutionCount) + ' resolved name entries. Hosts stay on the diagram after discovery, device shapes are inferred from capture metadata, and map zoom/export controls are enabled.';
  }

  function updateControlsEnabled(enabled) {
    for (const el of [els.playPause, els.back10, els.backStep, els.forwardStep, els.forward10, els.prevMatch, els.nextMatch, els.timeline, els.snapshot, els.savePng, els.exportFindings, els.resetView, els.clearFilters, els.maxNodes, els.hostSpacing, els.showAll]) {
      if (el) el.disabled = !enabled;
    }
    for (const el of [els.searchText, els.hostFilter, els.srcFilter, els.dstFilter, els.portFilter, els.preferDns, els.showIpUnderName]) {
      el.disabled = !enabled;
    }
  }

  function updatePlaybackButton() {
    els.playPause.textContent = state.playing ? 'Pause' : 'Play';
  }

  function setTime(t, seeking = false) {
    state.previousTime = state.currentTime;
    state.currentTime = Math.max(0, Math.min(state.duration, Number(t) || 0));
    els.timeline.value = String(state.currentTime);
    els.currentTime.textContent = formatDuration(state.currentTime);
    if (seeking) state.particles = [];
    state.needsRender = true;
  }

  function parsePortFilter(value) {
    const text = String(value || '').trim();
    if (!text) return [];
    const ranges = [];
    for (const token of text.split(/[\s,;]+/).filter(Boolean)) {
      const m = token.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
      if (!m) continue;
      const a = Math.max(0, Math.min(65535, Number(m[1])));
      const b = Math.max(0, Math.min(65535, Number(m[2] || m[1])));
      ranges.push({ a: Math.min(a, b), b: Math.max(a, b) });
    }
    return ranges;
  }

  function portMatches(port, ranges) {
    if (!Number.isFinite(port)) return false;
    for (const r of ranges) if (port >= r.a && port <= r.b) return true;
    return false;
  }

  function readFilters() {
    const textTokens = els.searchText.value.toLowerCase().split(/\s+/).filter(Boolean);
    const hostTokens = els.hostFilter.value.toLowerCase().split(/\s+/).filter(Boolean);
    const srcTokens = els.srcFilter.value.toLowerCase().split(/\s+/).filter(Boolean);
    const dstTokens = els.dstFilter.value.toLowerCase().split(/\s+/).filter(Boolean);
    const portRanges = parsePortFilter(els.portFilter.value);
    const protocols = new Set(Array.from(state.selectedProtocols).map(s => s.toLowerCase()));
    const active = textTokens.length || hostTokens.length || srcTokens.length || dstTokens.length || portRanges.length || protocols.size;
    return { textTokens, hostTokens, srcTokens, dstTokens, portRanges, protocols, active: Boolean(active) };
  }

  function tokensMatch(text, tokens) {
    if (!tokens.length) return true;
    text = String(text || '').toLowerCase();
    return tokens.every(t => text.includes(t));
  }

  function packetMatches(p, filters) {
    if (filters.protocols.size) {
      const protocol = String(p.protocol || '').toLowerCase();
      const service = String(p.service || '').toLowerCase();
      let ok = false;
      for (const wanted of filters.protocols) {
        if (protocol === wanted || service === wanted || protocol.includes(wanted) || service.includes(wanted)) { ok = true; break; }
      }
      if (!ok) return false;
    }
    if (filters.portRanges.length && !portMatches(p.sport, filters.portRanges) && !portMatches(p.dport, filters.portRanges)) return false;
    const srcText = hostSearchText(p.src);
    const dstText = hostSearchText(p.dst);
    if (!tokensMatch(srcText + ' ' + dstText, filters.hostTokens)) return false;
    if (!tokensMatch(srcText, filters.srcTokens)) return false;
    if (!tokensMatch(dstText, filters.dstTokens)) return false;
    if (!tokensMatch(p.search || '', filters.textTokens)) return false;
    return true;
  }


  function applyFilters(debounced = true) {
    if (!state.capture) return;
    if (debounced) {
      clearTimeout(state.filterDebounce);
      state.filterDebounce = setTimeout(() => applyFilters(false), 120);
      return;
    }
    const filters = readFilters();
    state.filters = filters;
    if (!filters.active) {
      state.filteredPackets = state.packets;
    } else {
      state.filteredPackets = state.packets.filter(p => packetMatches(p, filters));
    }
    state.filteredHostStats = buildHostStatsFromPackets(state.filteredPackets);
    rebuildHostSlots(state.filteredHostStats);
    state.layoutKey = '';
    state.particles = [];
    updateFilterStatus();
    state.needsRender = true;
  }

  function updateFilterStatus() {
    if (!state.capture) {
      els.filterStatus.innerHTML = 'Load a capture, then search by host name, IP address, port, protocol, service, DNS question, DNS answer, or flow text.';
      return;
    }
    const count = state.filteredPackets.length;
    const total = state.packets.length;
    const pct = total ? (count / total * 100) : 0;
    const activeBits = [];
    if (state.filters && state.filters.textTokens.length) activeBits.push('text');
    if (state.filters && state.filters.hostTokens.length) activeBits.push('host');
    if (state.filters && state.filters.srcTokens.length) activeBits.push('source');
    if (state.filters && state.filters.dstTokens.length) activeBits.push('destination');
    if (state.filters && state.filters.portRanges.length) activeBits.push('port');
    if (state.filters && state.filters.protocols.size) activeBits.push('protocol/service');
    const first = count ? formatDuration(state.filteredPackets[0].rel) : '--';
    const last = count ? formatDuration(state.filteredPackets[count - 1].rel) : '--';
    els.filterStatus.innerHTML = '<strong>' + fmtCount(count) + '</strong> of ' + fmtCount(total) + ' packets match (' + pct.toFixed(1) + '%). ' +
      '<span class="muted">Active filters: ' + (activeBits.length ? activeBits.join(', ') : 'none') + '. Match range: ' + first + ' to ' + last + '.</span>';
  }

  function clearFilters() {
    els.searchText.value = '';
    els.hostFilter.value = '';
    els.srcFilter.value = '';
    els.dstFilter.value = '';
    els.portFilter.value = '';
    state.selectedProtocols.clear();
    for (const btn of els.protocolChips.querySelectorAll('.chip.active')) btn.classList.remove('active');
    applyFilters(false);
  }

  function jumpMatch(direction) {
    if (!state.filteredPackets.length) return;
    const packets = state.filteredPackets;
    const t = state.currentTime;
    let idx;
    if (direction > 0) {
      idx = binarySearchPackets(packets, t + 0.001);
      if (idx >= packets.length) idx = 0;
    } else {
      idx = binarySearchPackets(packets, t - 0.001) - 1;
      if (idx < 0) idx = packets.length - 1;
    }
    setTime(packets[idx].rel, true);
  }

  function renderProtocolFilter(summary) {
    if (!summary) {
      els.protocolChips.innerHTML = '<span class="muted">Protocols appear after a capture is loaded.</span>';
      return;
    }
    const order = [];
    const seen = new Set();
    function add(name, count) {
      if (!name) return;
      const key = String(name).toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      order.push({ name: String(name), count: Number(count || 0) });
    }
    for (const [name, count] of summary.protocolCounts || []) add(name, count);
    for (const [name, count] of summary.serviceCounts || []) {
      if (/^(DNS|MDNS|LLMNR|HTTP|HTTPS|QUIC|DHCP|NTP|SSDP|SMB|RDP|SSH|ARP|ICMP|ICMPv6|UDP|TCP)/i.test(name)) add(name, count);
    }
    els.protocolChips.innerHTML = order.slice(0, 28).map(item => '<button type="button" class="chip" data-protocol="' + escapeAttr(item.name) + '">' + escapeHtml(item.name) + ' <span>' + fmtCount(item.count) + '</span></button>').join('');
  }

  function buildWindowView() {
    const packets = state.filteredPackets || [];
    const start = state.currentTime;
    const end = Math.min(state.duration, start + state.windowSec);
    const i = binarySearchPackets(packets, start);
    const viewPackets = [];
    const hosts = new Map();
    const edges = new Map();
    const protocolCounts = {};
    let bytes = 0;
    for (let j = i; j < packets.length; j++) {
      const p = packets[j];
      if (p.rel > end) break;
      viewPackets.push(p);
      bytes += p.bytes || 0;
      bumpObj(protocolCounts, p.service || p.protocol, 1);
      if (!hosts.has(p.src)) hosts.set(p.src, { host: p.src, sent: 0, recv: 0, bytes: 0, packets: 0 });
      if (!hosts.has(p.dst)) hosts.set(p.dst, { host: p.dst, sent: 0, recv: 0, bytes: 0, packets: 0 });
      const sh = hosts.get(p.src);
      const dh = hosts.get(p.dst);
      sh.sent += 1; sh.bytes += p.bytes || 0; sh.packets += 1;
      dh.recv += 1; dh.bytes += p.bytes || 0; dh.packets += 1;
      const key = p.src + '\u0000' + p.dst + '\u0000' + (p.service || p.protocol) + '\u0000' + (p.sport || '') + '\u0000' + (p.dport || '');
      if (!edges.has(key)) edges.set(key, { key, src: p.src, dst: p.dst, protocol: p.protocol, service: p.service || p.protocol, sport: p.sport, dport: p.dport, packets: 0, bytes: 0, lastRel: p.rel, detail: p.detail || '' });
      const e = edges.get(key);
      e.packets += 1;
      e.bytes += p.bytes || 0;
      e.lastRel = p.rel;
      if (p.detail) e.detail = p.detail;
    }
    const edgeList = Array.from(edges.values()).sort((a, b) => b.packets - a.packets || b.bytes - a.bytes);
    return { start, end, packets: viewPackets, hosts, edges: edgeList, protocolCounts, bytes };
  }

  function bumpObj(obj, key, inc) { obj[key] = (obj[key] || 0) + inc; }

  function packetsBetween(t0, t1) {
    const packets = state.filteredPackets || [];
    if (!packets.length || t1 <= t0) return [];
    const i = binarySearchPackets(packets, t0);
    const j = binarySearchPackets(packets, t1 + 0.000001);
    const count = j - i;
    if (count <= 0) return [];
    const limit = 220;
    if (count <= limit) return packets.slice(i, j);
    const stride = Math.ceil(count / limit);
    const sample = [];
    for (let k = i; k < j; k += stride) sample.push(packets[k]);
    return sample;
  }

  function visibleNodesForView(view) {
    const nodeMap = new Map();
    for (const h of view.hosts.values()) {
      const meta = state.hostIndex.get(h.host) || {};
      nodeMap.set(h.host, {
        host: h.host,
        label: meta.label || hostLabel(h.host),
        className: meta.className || classifyHost(h.host),
        active: true,
        windowPackets: h.packets,
        windowBytes: h.bytes,
        totalPackets: meta.totalPackets || h.packets,
        totalBytes: meta.totalBytes || h.bytes,
        firstSeen: meta.firstSeen,
        deviceType: meta.deviceType || inferDeviceType(meta),
        deviceInterest: state.devicesOfInterest.has(h.host)
      });
    }
    if (state.showAll) {
      const cutoff = Math.min(state.duration, state.currentTime + state.windowSec + 0.000001);
      for (const host of state.hostOrder || []) {
        if (nodeMap.size >= state.maxNodes) break;
        const meta = state.hostIndex.get(host) || {};
        const firstSeen = Number.isFinite(meta.firstSeen) ? meta.firstSeen : Infinity;
        if (firstSeen > cutoff) continue;
        if (!nodeMap.has(host)) nodeMap.set(host, {
          host,
          label: meta.label || hostLabel(host),
          className: meta.className || classifyHost(host),
          active: false,
          windowPackets: 0,
          windowBytes: 0,
          totalPackets: meta.totalPackets || 0,
          totalBytes: meta.totalBytes || 0,
          firstSeen,
          deviceType: meta.deviceType || inferDeviceType(meta),
          deviceInterest: state.devicesOfInterest.has(host)
        });
      }
    }
    let nodes = Array.from(nodeMap.values());
    nodes.forEach(n => { n.slot = state.hostSlots.has(n.host) ? state.hostSlots.get(n.host) : Number.MAX_SAFE_INTEGER; });
    nodes.sort((a, b) => (a.slot - b.slot) || Number(b.active) - Number(a.active) || b.windowPackets - a.windowPackets || b.totalPackets - a.totalPackets || a.host.localeCompare(b.host));
    nodes = nodes.slice(0, state.maxNodes);
    return nodes;
  }

  function computeLayout(nodes) {
    const w = state.dimensions.w;
    const h = state.dimensions.h;
    const ordered = nodes.slice().sort((a, b) => (a.slot - b.slot) || a.host.localeCompare(b.host));
    const key = w + 'x' + h + '|' + state.hostSpacing.toFixed(2) + '|' + ordered.map(n => n.host).join('|');
    if (key === state.layoutKey && state.layout.size) return state.layout;
    state.layoutKey = key;
    const layout = new Map();
    const n = ordered.length;
    if (!n) { state.layout = layout; return layout; }

    const padLeft = 76, padRight = 76, padTop = 54, padBottom = 96;
    const availW = Math.max(180, w - padLeft - padRight);
    const availH = Math.max(180, h - padTop - padBottom);
    const baseCellW = 132 * state.hostSpacing;
    const baseCellH = 104 * state.hostSpacing;
    const minCellW = 74;
    const maxCols = Math.max(1, Math.min(n, Math.floor(availW / minCellW)));
    let best = null;
    for (let cols = 1; cols <= maxCols; cols++) {
      const rows = Math.ceil(n / cols);
      const scale = Math.min(1, availW / (cols * baseCellW), availH / (rows * baseCellH));
      const fill = scale * Math.min(1, cols / Math.max(1, rows));
      if (!best || scale > best.scale + 1e-9 || (Math.abs(scale - best.scale) < 1e-9 && fill > best.fill)) {
        best = { cols, rows, scale, fill };
      }
    }
    const cols = best.cols;
    const rows = best.rows;
    const cellW = Math.max(minCellW, baseCellW * best.scale);
    const cellH = Math.max(68, baseCellH * best.scale);
    const usedW = Math.min(availW, cols * cellW);
    const usedH = Math.min(availH, rows * cellH);
    const offsetX = padLeft + Math.max(0, (availW - usedW) / 2);
    const offsetY = padTop + Math.max(0, (availH - usedH) / 2);

    ordered.forEach((node, index) => {
      const col = index % cols;
      const row = Math.floor(index / cols);
      const x = offsetX + col * cellW + cellW / 2;
      const y = offsetY + row * cellH + cellH / 2;
      layout.set(node.host, { x, y, r: nodeRadius(node), node });
    });

    state.layout = layout;
    return layout;
  }

  function nodeRadius(node) {
    const score = (node.windowPackets || 0) * 3.2 + Math.log10((node.totalPackets || 1) + 1) * 7.2;
    const cap = Math.max(16, Math.min(22, 14 + (state.hostSpacing - 1) * 4));
    return Math.max(6, Math.min(cap, 6 + score));
  }

  function updateDimensions() {
    const rect = els.graphShell.getBoundingClientRect();
    const w = Math.max(640, Math.floor(rect.width));
    const h = Math.max(420, Math.floor(rect.height));
    if (w !== state.dimensions.w || h !== state.dimensions.h) {
      state.dimensions = { w, h };
      els.graphSvg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
      drawGrid();
      applyGraphTransform();
      state.layoutKey = '';
    }
  }

  function drawGrid() {
    const w = state.dimensions.w, h = state.dimensions.h;
    const step = 80;
    let html = '';
    for (let x = step; x < w; x += step) html += '<line class="grid-line" x1="' + x + '" y1="0" x2="' + x + '" y2="' + h + '"></line>';
    for (let y = step; y < h; y += step) html += '<line class="grid-line" x1="0" y1="' + y + '" x2="' + w + '" y2="' + y + '"></line>';
    els.gridLayer.innerHTML = html;
    applyGraphTransform();
  }

  function renderEmptyGraph() {
    updateDimensions();
    drawGrid();
    els.edgesLayer.innerHTML = '';
    els.particlesLayer.innerHTML = '';
    els.nodesLayer.innerHTML = '';
  }

  function addParticles(crossed, layout, now) {
    if (!crossed || !crossed.length) return;
    for (const p of crossed) {
      if (!layout.has(p.src) || !layout.has(p.dst)) continue;
      state.particles.push({ src: p.src, dst: p.dst, protocol: p.service || p.protocol, bytes: p.bytes || 0, created: now, ttl: 850 + Math.min(600, Math.log10((p.bytes || 1) + 1) * 110) });
    }
    if (state.particles.length > 700) state.particles.splice(0, state.particles.length - 700);
  }



  function deviceShapeLabel(type) {
    return ({ workstation: 'Workstation', server: 'Server', router: 'Router / infrastructure', printer: 'Printer', cloud: 'Remote host / cloud', multicast: 'Multicast', broadcast: 'Broadcast', adapter: 'MAC / adapter', device: 'Network device', unknown: 'Unknown device' })[type] || 'Network device';
  }

  function pointsString(points) {
    return points.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
  }

  function starPoints(cx, cy, outer, inner, count = 5) {
    const pts = [];
    for (let i = 0; i < count * 2; i++) {
      const r = i % 2 ? inner : outer;
      const a = -Math.PI / 2 + i * Math.PI / count;
      pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]);
    }
    return pointsString(pts);
  }

  function nodeShapeSvg(node, p) {
    const x = p.x, y = p.y, r = p.r;
    const type = node.deviceType || 'device';
    const cls = 'node-shape';
    let html = '';
    if (type === 'server') {
      const w = r * 2.2, h = r * 2.55;
      html += '<rect class="' + cls + '" x="' + (x - w / 2).toFixed(1) + '" y="' + (y - h / 2).toFixed(1) + '" width="' + w.toFixed(1) + '" height="' + h.toFixed(1) + '" rx="4"></rect>';
      html += '<line class="device-detail" x1="' + (x - w * 0.32).toFixed(1) + '" y1="' + (y - h * 0.12).toFixed(1) + '" x2="' + (x + w * 0.32).toFixed(1) + '" y2="' + (y - h * 0.12).toFixed(1) + '"></line>';
      html += '<line class="device-detail" x1="' + (x - w * 0.32).toFixed(1) + '" y1="' + (y + h * 0.16).toFixed(1) + '" x2="' + (x + w * 0.32).toFixed(1) + '" y2="' + (y + h * 0.16).toFixed(1) + '"></line>';
    } else if (type === 'workstation') {
      const w = r * 2.55, h = r * 1.65;
      html += '<rect class="' + cls + '" x="' + (x - w / 2).toFixed(1) + '" y="' + (y - h / 2).toFixed(1) + '" width="' + w.toFixed(1) + '" height="' + h.toFixed(1) + '" rx="4"></rect>';
      html += '<line class="device-detail" x1="' + x.toFixed(1) + '" y1="' + (y + h / 2).toFixed(1) + '" x2="' + x.toFixed(1) + '" y2="' + (y + h / 2 + r * 0.55).toFixed(1) + '"></line>';
      html += '<line class="device-detail" x1="' + (x - r * 0.85).toFixed(1) + '" y1="' + (y + h / 2 + r * 0.55).toFixed(1) + '" x2="' + (x + r * 0.85).toFixed(1) + '" y2="' + (y + h / 2 + r * 0.55).toFixed(1) + '"></line>';
    } else if (type === 'router') {
      const pts = [[x, y - r * 1.25], [x + r * 1.25, y - r * 0.45], [x + r * 1.25, y + r * 0.72], [x, y + r * 1.32], [x - r * 1.25, y + r * 0.72], [x - r * 1.25, y - r * 0.45]];
      html += '<polygon class="' + cls + '" points="' + pointsString(pts) + '"></polygon>';
      html += '<path class="device-detail" d="M' + (x - r * 0.70).toFixed(1) + ',' + y.toFixed(1) + ' H' + (x + r * 0.70).toFixed(1) + ' M' + x.toFixed(1) + ',' + (y - r * 0.68).toFixed(1) + ' V' + (y + r * 0.68).toFixed(1) + '"></path>';
    } else if (type === 'printer') {
      const w = r * 2.55, h = r * 1.45;
      html += '<rect class="' + cls + '" x="' + (x - w / 2).toFixed(1) + '" y="' + (y - h * 0.15).toFixed(1) + '" width="' + w.toFixed(1) + '" height="' + h.toFixed(1) + '" rx="4"></rect>';
      html += '<rect class="device-detail" x="' + (x - w * 0.34).toFixed(1) + '" y="' + (y - h * 0.70).toFixed(1) + '" width="' + (w * 0.68).toFixed(1) + '" height="' + (h * 0.48).toFixed(1) + '" rx="2"></rect>';
      html += '<line class="device-detail" x1="' + (x - w * 0.30).toFixed(1) + '" y1="' + (y + h * 0.40).toFixed(1) + '" x2="' + (x + w * 0.30).toFixed(1) + '" y2="' + (y + h * 0.40).toFixed(1) + '"></line>';
    } else if (type === 'cloud') {
      html += '<path class="' + cls + '" d="M' + (x - r * 1.25).toFixed(1) + ',' + (y + r * 0.25).toFixed(1) + ' C' + (x - r * 1.58).toFixed(1) + ',' + (y - r * 0.45).toFixed(1) + ' ' + (x - r * 0.72).toFixed(1) + ',' + (y - r * 1.08).toFixed(1) + ' ' + (x - r * 0.08).toFixed(1) + ',' + (y - r * 0.75).toFixed(1) + ' C' + (x + r * 0.35).toFixed(1) + ',' + (y - r * 1.46).toFixed(1) + ' ' + (x + r * 1.48).toFixed(1) + ',' + (y - r * 0.86).toFixed(1) + ' ' + (x + r * 1.08).toFixed(1) + ',' + (y - r * 0.05).toFixed(1) + ' C' + (x + r * 1.78).toFixed(1) + ',' + (y + r * 0.02).toFixed(1) + ' ' + (x + r * 1.54).toFixed(1) + ',' + (y + r * 0.88).toFixed(1) + ' ' + (x + r * 0.70).toFixed(1) + ',' + (y + r * 0.88).toFixed(1) + ' H' + (x - r * 0.92).toFixed(1) + ' C' + (x - r * 1.64).toFixed(1) + ',' + (y + r * 0.88).toFixed(1) + ' ' + (x - r * 1.82).toFixed(1) + ',' + (y + r * 0.36).toFixed(1) + ' ' + (x - r * 1.25).toFixed(1) + ',' + (y + r * 0.25).toFixed(1) + ' Z"></path>';
    } else if (type === 'multicast') {
      html += '<polygon class="' + cls + '" points="' + pointsString([[x, y - r * 1.45], [x + r * 1.45, y], [x, y + r * 1.45], [x - r * 1.45, y]]) + '"></polygon>';
    } else if (type === 'broadcast') {
      html += '<polygon class="' + cls + '" points="' + pointsString([[x, y - r * 1.55], [x + r * 1.42, y + r * 1.12], [x - r * 1.42, y + r * 1.12]]) + '"></polygon>';
    } else if (type === 'adapter') {
      const w = r * 2.45, h = r * 1.85;
      html += '<rect class="' + cls + '" x="' + (x - w / 2).toFixed(1) + '" y="' + (y - h / 2).toFixed(1) + '" width="' + w.toFixed(1) + '" height="' + h.toFixed(1) + '" rx="3"></rect>';
      for (let i = -2; i <= 2; i++) html += '<line class="device-detail" x1="' + (x + i * w / 5).toFixed(1) + '" y1="' + (y - h / 2).toFixed(1) + '" x2="' + (x + i * w / 5).toFixed(1) + '" y2="' + (y - h / 2 - r * 0.35).toFixed(1) + '"></line>';
    } else {
      html += '<rect class="' + cls + '" x="' + (x - r * 1.15).toFixed(1) + '" y="' + (y - r * 1.15).toFixed(1) + '" width="' + (r * 2.3).toFixed(1) + '" height="' + (r * 2.3).toFixed(1) + '" rx="' + (r * 0.35).toFixed(1) + '"></rect>';
    }
    if (node.deviceInterest) {
      html += '<polygon class="interest-star" points="' + starPoints(x + r * 1.35, y - r * 1.35, Math.max(5, r * 0.42), Math.max(2.5, r * 0.18)) + '"></polygon>';
    }
    return html;
  }

  function renderGraph(view, crossed, now) {
    updateDimensions();
    const nodes = visibleNodesForView(view);
    const layout = computeLayout(nodes);
    const visible = new Set(nodes.map(n => n.host));
    addParticles(crossed, layout, now);

    const maxEdges = 700;
    const edges = view.edges.filter(e => visible.has(e.src) && visible.has(e.dst)).slice(0, maxEdges);
    let edgeHtml = '';
    const maxPkts = Math.max(1, ...edges.map(e => e.packets));
    edges.forEach((e, idx) => {
      const a = layout.get(e.src), b = layout.get(e.dst);
      if (!a || !b) return;
      const dx = b.x - a.x, dy = b.y - a.y;
      const len = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const ux = dx / len, uy = dy / len;
      const startX = a.x + ux * (a.r + 2), startY = a.y + uy * (a.r + 2);
      const endX = b.x - ux * (b.r + 5), endY = b.y - uy * (b.r + 5);
      const curve = ((hashString(e.key) % 1000) / 1000 - 0.5) * 48;
      const mx = (startX + endX) / 2 - uy * curve;
      const my = (startY + endY) / 2 + ux * curve;
      const width = 1.1 + Math.log1p(e.packets) / Math.log1p(maxPkts) * 5.4;
      const cls = protocolClass(e.service || e.protocol);
      edgeHtml += '<path class="edge ' + cls + '" d="M' + startX.toFixed(1) + ',' + startY.toFixed(1) + ' Q' + mx.toFixed(1) + ',' + my.toFixed(1) + ' ' + endX.toFixed(1) + ',' + endY.toFixed(1) + '" stroke-width="' + width.toFixed(2) + '" marker-end="url(#arrow)"><title>' + escapeHtml(hostDisplay(e.src) + ' -> ' + hostDisplay(e.dst) + ' ' + e.service + ' ' + e.packets + ' packets') + '</title></path>';
      if (idx < 34) {
        edgeHtml += '<text class="edge-label" x="' + mx.toFixed(1) + '" y="' + my.toFixed(1) + '" text-anchor="middle">' + escapeHtml(e.service + ' ' + e.packets) + '</text>';
      }
    });
    els.edgesLayer.innerHTML = edgeHtml;

    const alive = [];
    let particleHtml = '';
    for (const part of state.particles) {
      const age = now - part.created;
      if (age > part.ttl) continue;
      const a = layout.get(part.src), b = layout.get(part.dst);
      if (!a || !b) continue;
      const t = Math.max(0, Math.min(1, age / part.ttl));
      const ease = 1 - Math.pow(1 - t, 2);
      const x = a.x + (b.x - a.x) * ease;
      const y = a.y + (b.y - a.y) * ease;
      const size = Math.max(2.5, Math.min(8, 2.5 + Math.log10(part.bytes + 1)));
      const opacity = Math.max(0, 1 - t);
      const cls = protocolClass(part.protocol);
      particleHtml += '<circle class="particle ' + cls + '" cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="' + size.toFixed(1) + '" opacity="' + opacity.toFixed(2) + '"></circle>';
      alive.push(part);
    }
    state.particles = alive;
    els.particlesLayer.innerHTML = particleHtml;

    let nodeHtml = '';
    for (const n of nodes) {
      const p = layout.get(n.host);
      if (!p) continue;
      const label = hostLabel(n.host);
      const sub = state.showIpUnderName && label !== n.host ? n.host : '';
      const deviceType = n.deviceType || 'device';
      const cls = 'node ' + (n.className || 'remote') + ' device-' + deviceType + (n.deviceInterest ? ' device-interest' : '') + (n.active ? '' : ' inactive') + (state.selectedHost === n.host ? ' selected' : '');
      const title = hostDisplay(n.host) + '\nDevice type: ' + deviceShapeLabel(deviceType) + '\nPackets now: ' + n.windowPackets + '\nTotal packets: ' + n.totalPackets + (n.deviceInterest ? '\nMarked as Device of Interest' : '');
      nodeHtml += '<g class="' + cls + '" data-host="' + escapeAttr(n.host) + '"><title>' + escapeHtml(title) + '</title>';
      if (state.selectedHost === n.host) nodeHtml += '<circle class="halo" cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="' + (p.r + 14).toFixed(1) + '"></circle>';
      nodeHtml += nodeShapeSvg(n, p);
      nodeHtml += '<text x="' + p.x.toFixed(1) + '" y="' + (p.y + p.r + 20).toFixed(1) + '" text-anchor="middle">' + escapeHtml(shortenHost(label, 28)) + '</text>';
      if (sub) nodeHtml += '<text class="subtext" x="' + p.x.toFixed(1) + '" y="' + (p.y + p.r + 33).toFixed(1) + '" text-anchor="middle">' + escapeHtml(shortenHost(sub, 24)) + '</text>';
      nodeHtml += '</g>';
    }
    els.nodesLayer.innerHTML = nodeHtml;
    applyGraphTransform();
  }

  function renderSidePanels(view, force = false) {
    const now = performance.now();
    if (!force && now - state.lastPanelAt < 180) return;
    state.lastPanelAt = now;
    state.lastView = view;
    els.windowRange.textContent = formatDuration(view.start) + ' - ' + formatDuration(view.end);
    els.windowPackets.textContent = fmtCount(view.packets.length);
    els.windowHosts.textContent = fmtCount(view.hosts.size);
    els.windowBytes.textContent = fmtBytes(view.bytes);
    els.windowEdges.textContent = fmtCount(view.edges.length);
    renderProtocols(view.protocolCounts);
    renderTopFlows(view.edges);
    renderPacketHits(view.packets);
    renderHostPanel(state.selectedHost, view);
  }

  function renderSummary(summary) {
    if (!summary) {
      els.summaryPanel.innerHTML = '<div class="kv"><span class="k">Status</span><span class="v">No capture loaded</span></div>';
      return;
    }
    const linkTypes = Object.entries(summary.linkTypes || {}).map(([k, v]) => k + ' (' + v + ')').join(', ') || '--';
    const warnings = (summary.warnings || []).slice(0, 3).join(' | ');
    els.summaryPanel.innerHTML = [
      kv('Type', summary.fileType || 'pcapng'),
      kv('Packets', fmtCount(summary.packetsDecoded)),
      kv('Bytes decoded', fmtBytes(summary.bytesDecoded)),
      kv('Duration', formatDuration(summary.duration)),
      kv('First packet', formatAbsTimestamp(summary.firstTs)),
      kv('Last packet', formatAbsTimestamp(summary.lastTs)),
      kv('Hosts', fmtCount(summary.hostCount)),
      kv('DNS packets', fmtCount(summary.dnsPacketCount || 0)),
      kv('Resolved names', fmtCount(summary.dnsResolutionCount || 0)),
      kv('Link types', linkTypes),
      warnings ? kv('Warnings', warnings) : ''
    ].join('');
  }

  function renderDnsPanel(dns) {
    if (!dns) {
      els.dnsPanel.innerHTML = '<div class="kv"><span class="k">Status</span><span class="v">DNS names appear after parsing DNS, mDNS, LLMNR, or PCAPNG NRB records.</span></div>';
      return;
    }
    const rows = (dns.resolutions || []).slice(0, 12).map(r => '<tr><td>' + escapeHtml(shortenHost(r.name, 32)) + '</td><td>' + escapeHtml(shortenHost(r.address, 22)) + '</td><td class="num">' + fmtCount(r.count) + '</td></tr>').join('');
    const queries = (dns.queryCounts || []).slice(0, 8).map(([name, count]) => '<span class="pill">' + escapeHtml(shortenHost(name, 28)) + ' <strong>' + fmtCount(count) + '</strong></span>').join(' ');
    els.dnsPanel.innerHTML =
      '<div class="kv"><span class="k">DNS packets</span><span class="v">' + fmtCount(dns.dnsPacketCount || 0) + '</span></div>' +
      '<div class="kv"><span class="k">Name entries</span><span class="v">' + fmtCount((dns.resolutions || []).length) + '</span></div>' +
      '<table class="mini-table"><thead><tr><th>Name</th><th>Address</th><th class="num">Hits</th></tr></thead><tbody>' + (rows || '<tr><td colspan="3" class="muted">No address answers found</td></tr>') + '</tbody></table>' +
      '<div class="chip-note">Top DNS questions</div><div class="pill-wrap">' + (queries || '<span class="muted">No DNS questions decoded</span>') + '</div>';
  }

  function kv(k, v) {
    return '<div class="kv"><span class="k">' + escapeHtml(k) + '</span><span class="v">' + escapeHtml(v) + '</span></div>';
  }

  function renderProtocols(protocolCounts) {
    const entries = Object.entries(protocolCounts || {}).sort((a, b) => b[1] - a[1]).slice(0, 14);
    if (!entries.length) {
      els.protocolLegend.innerHTML = '<span class="muted">No packets in this window</span>';
      return;
    }
    els.protocolLegend.innerHTML = entries.map(([name, count]) => '<span class="pill"><span class="dot ' + protocolClass(name) + '"></span>' + escapeHtml(name) + ' ' + fmtCount(count) + '</span>').join('');
  }

  function renderTopFlows(edges) {
    const top = (edges || []).slice(0, 12);
    if (!top.length) {
      els.topFlows.innerHTML = '<tr><td colspan="4" class="muted">No packets in this window</td></tr>';
      return;
    }
    els.topFlows.innerHTML = top.map(e => '<tr><td>' + escapeHtml(shortenHost(hostDisplay(e.src), 24)) + ' -> ' + escapeHtml(shortenHost(hostDisplay(e.dst), 24)) + '</td><td>' + escapeHtml(e.service || e.protocol) + '</td><td>' + escapeHtml(portPair(e)) + '</td><td class="num">' + fmtCount(e.packets) + '</td></tr>').join('');
  }

  function portPair(e) {
    if (Number.isFinite(e.sport) && Number.isFinite(e.dport)) return e.sport + ' -> ' + e.dport;
    return '--';
  }

  function renderPacketHits(packets) {
    const rows = (packets || []).slice(0, 12).map(p => '<tr><td>' + escapeHtml(formatDuration(p.rel)) + '</td><td>' + escapeHtml(shortenHost(hostDisplay(p.src), 22)) + ' -> ' + escapeHtml(shortenHost(hostDisplay(p.dst), 22)) + '</td><td>' + escapeHtml(p.service || p.protocol) + '</td><td>' + escapeHtml(shortenHost(p.detail || portPair(p), 36)) + '</td></tr>').join('');
    els.packetHits.innerHTML = rows || '<tr><td colspan="4" class="muted">No matching packets in this window</td></tr>';
  }

  function renderHostPanel(host, view) {
    if (!host) {
      els.hostPanel.innerHTML = '<div class="kv"><span class="k">Tip</span><span class="v">Click a device to pin host details here. DNS aliases are searchable. Mark important devices before exporting findings.</span></div>';
      return;
    }
    const meta = state.hostIndex.get(host) || { host, label: hostLabel(host), names: [], className: classifyHost(host), deviceType: 'device' };
    const current = view && view.hosts ? view.hosts.get(host) : null;
    const names = (meta.names || []).slice(0, 12).map(n => '<span class="pill">' + escapeHtml(shortenHost(n, 34)) + '</span>').join(' ');
    const marked = state.devicesOfInterest.has(host);
    els.hostPanel.innerHTML = [
      kv('Display', hostDisplay(host)),
      kv('Address', host),
      kv('Class', meta.className || classifyHost(host)),
      kv('Device type', deviceShapeLabel(meta.deviceType || inferDeviceType(meta))),
      kv('Finding status', marked ? 'Device of Interest' : 'Not marked'),
      kv('Total packets', fmtCount(meta.totalPackets || 0)),
      kv('Total bytes', fmtBytes(meta.totalBytes || 0)),
      kv('Sent / recv', fmtCount(meta.sentPackets || 0) + ' / ' + fmtCount(meta.recvPackets || 0)),
      kv('Now sent / recv', current ? (fmtCount(current.sent) + ' / ' + fmtCount(current.recv)) : '0 / 0'),
      '<div class="chip-note">Known DNS names</div><div class="pill-wrap">' + (names || '<span class="muted">No DNS alias decoded for this host</span>') + '</div>',
      '<button class="small-button" id="filterThisHost" type="button" title="Filter packets to this host">Filter this host</button> ',
      '<button class="small-button" id="toggleInterestHost" type="button" title="Include or remove this device from Export Findings">' + (marked ? 'Remove Device of Interest' : 'Mark Device of Interest') + '</button>'
    ].join('');
    const btn = document.getElementById('filterThisHost');
    if (btn) btn.onclick = () => { els.hostFilter.value = hostDisplay(host, false); applyFilters(false); };
    const interestBtn = document.getElementById('toggleInterestHost');
    if (interestBtn) interestBtn.onclick = () => {
      if (state.devicesOfInterest.has(host)) state.devicesOfInterest.delete(host);
      else state.devicesOfInterest.add(host);
      state.needsRender = true;
      renderHostPanel(host, state.lastView);
      updateDevicesOfInterestList();
    };
  }

  function renderFrame(now, force = false, crossed = []) {
    if (!state.capture) return;
    const view = buildWindowView();
    renderGraph(view, crossed, now);
    renderSidePanels(view, force);
    state.needsRender = false;
  }

  function animationLoop(now) {
    if (!state.lastFrameAt) state.lastFrameAt = now;
    const dt = Math.min(0.25, (now - state.lastFrameAt) / 1000);
    state.lastFrameAt = now;
    let crossed = [];
    if (state.playing && state.capture) {
      const old = state.currentTime;
      const next = Math.min(state.duration, old + dt * state.speed);
      state.previousTime = old;
      state.currentTime = next;
      els.timeline.value = String(next);
      els.currentTime.textContent = formatDuration(next);
      crossed = packetsBetween(old, next);
      if (next >= state.duration) {
        state.playing = false;
        updatePlaybackButton();
      }
      state.needsRender = true;
    }
    if (state.capture && (state.needsRender || state.particles.length || state.playing)) renderFrame(now, false, crossed);
    state.fpsFrames += 1;
    if (now - state.fpsStarted > 700) {
      els.fps.textContent = Math.round(state.fpsFrames * 1000 / (now - state.fpsStarted)) + ' fps';
      state.fpsFrames = 0;
      state.fpsStarted = now;
    }
    requestAnimationFrame(animationLoop);
  }

  function svgStyleText() {
    return `
      .grid-line{stroke:rgba(148,163,184,.14);stroke-width:1}.edge{fill:none;stroke-linecap:round;opacity:.72}.edge.tcp{stroke:${cssVar('--tcp','#38bdf8')}}.edge.udp{stroke:${cssVar('--udp','#a78bfa')}}.edge.arp{stroke:${cssVar('--arp','#fbbf24')}}.edge.icmp{stroke:${cssVar('--icmp','#fb7185')}}.edge.other{stroke:${cssVar('--other','#cbd5e1')}}.edge-label{fill:${cssVar('--text','#e2e8f0')};font-size:10px;paint-order:stroke;stroke:${cssVar('--export-bg','#08111f')};stroke-width:3px}.particle.tcp{fill:${cssVar('--tcp','#38bdf8')}}.particle.udp{fill:${cssVar('--udp','#a78bfa')}}.particle.arp{fill:${cssVar('--arp','#fbbf24')}}.particle.icmp{fill:${cssVar('--icmp','#fb7185')}}.particle.other{fill:${cssVar('--other','#cbd5e1')}}.node text{fill:${cssVar('--text','#f8fafc')};font-size:11px;font-weight:650;paint-order:stroke;stroke:${cssVar('--node-label-stroke','rgba(2,6,23,.75)')};stroke-width:3px}.node .subtext{fill:${cssVar('--muted','#94a3b8')};font-size:9px}.node-shape{stroke-width:1.8;vector-effect:non-scaling-stroke}.node.local .node-shape{fill:rgba(52,211,153,.92);stroke:#bbf7d0}.node.remote .node-shape{fill:rgba(96,165,250,.88);stroke:#bfdbfe}.node.mac .node-shape{fill:rgba(251,191,36,.88);stroke:#fde68a}.node.multicast .node-shape{fill:rgba(244,114,182,.88);stroke:#fbcfe8}.node.broadcast .node-shape{fill:rgba(251,113,133,.9);stroke:#fecdd3}.node.device-server .node-shape{fill:rgba(56,189,248,.85)}.node.device-router .node-shape{fill:rgba(167,139,250,.86)}.node.device-printer .node-shape{fill:rgba(251,191,36,.9)}.node.device-workstation .node-shape{fill:rgba(52,211,153,.86)}.node.device-cloud .node-shape{fill:rgba(96,165,250,.76)}.node.device-interest .node-shape{stroke:${cssVar('--warn','#f59e0b')};stroke-width:3}.device-detail{fill:rgba(2,6,23,.34);stroke:rgba(248,250,252,.62);stroke-width:1;vector-effect:non-scaling-stroke}.interest-star{fill:${cssVar('--warn','#f59e0b')};stroke:rgba(2,6,23,.78);stroke-width:1.5}.halo{fill:none;stroke:rgba(56,189,248,.34);stroke-width:9}
    `;
  }

  function serializeGraphSvg() {
    const clone = els.graphSvg.cloneNode(true);
    clone.setAttribute('xmlns', SVG_NS);
    clone.setAttribute('width', String(state.dimensions.w));
    clone.setAttribute('height', String(state.dimensions.h));
    const style = document.createElementNS(SVG_NS, 'style');
    style.textContent = svgStyleText();
    const bg = document.createElementNS(SVG_NS, 'rect');
    bg.setAttribute('x', '0');
    bg.setAttribute('y', '0');
    bg.setAttribute('width', String(state.dimensions.w));
    bg.setAttribute('height', String(state.dimensions.h));
    bg.setAttribute('fill', cssVar('--export-bg', '#08111f'));
    clone.insertBefore(bg, clone.firstChild);
    clone.insertBefore(style, clone.firstChild);
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(clone);
  }

  function saveSvg() {
    const source = serializeGraphSvg();
    const blob = new Blob([source], { type: 'image/svg+xml' });
    downloadBlob(blob, 'pcap-visualizer-' + Math.round(state.currentTime) + 's.svg');
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 250);
  }

  function graphPngBlob() {
    const source = serializeGraphSvg();
    const svgBlob = new Blob([source], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(svgBlob);
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          canvas.width = state.dimensions.w;
          canvas.height = state.dimensions.h;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0);
          canvas.toBlob(blob => {
            URL.revokeObjectURL(url);
            if (blob) resolve(blob);
            else reject(new Error('Could not render PNG'));
          }, 'image/png');
        } catch (error) { URL.revokeObjectURL(url); reject(error); }
      };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Could not load SVG for PNG rendering')); };
      img.src = url;
    });
  }

  async function savePng() {
    if (!state.capture) return;
    try {
      const blob = await graphPngBlob();
      downloadBlob(blob, 'pcap-visualizer-' + Math.round(state.currentTime) + 's.png');
    } catch (error) {
      alert('PNG export failed: ' + (error && error.message ? error.message : error));
    }
  }

  function updateDevicesOfInterestList() {
    if (!els.devicesOfInterestList) return;
    const hosts = Array.from(state.devicesOfInterest);
    if (!hosts.length) {
      els.devicesOfInterestList.innerHTML = '<span class="muted">No devices marked yet. Select a device and choose Mark Device of Interest.</span>';
      return;
    }
    els.devicesOfInterestList.innerHTML = hosts.map(host => {
      const meta = state.hostIndex.get(host) || { host };
      return '<span class="pill" title="' + escapeAttr(host) + '">' + escapeHtml(shortenHost(hostDisplay(host), 42)) + ' · ' + escapeHtml(deviceShapeLabel(meta.deviceType || inferDeviceType(meta))) + '</span>';
    }).join('');
  }

  function openFindingsModal() {
    if (!state.capture) return;
    updateDevicesOfInterestList();
    if (els.findingLabel && !els.findingLabel.value) els.findingLabel.value = 'Network finding at ' + formatDuration(state.currentTime);
    els.findingsModal.classList.remove('hidden');
    setTimeout(() => els.findingLabel && els.findingLabel.focus(), 0);
  }

  function closeFindingsModal() {
    els.findingsModal.classList.add('hidden');
  }

  function crc32(bytes) {
    let table = crc32.table;
    if (!table) {
      table = crc32.table = new Uint32Array(256);
      for (let i = 0; i < 256; i++) {
        let c = i;
        for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        table[i] = c >>> 0;
      }
    }
    let c = 0xffffffff;
    for (const b of bytes) c = table[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  function dosDateTime(date = new Date()) {
    const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
    const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
    return { time, day };
  }

  function u16(arr, n) { arr.push(n & 255, (n >>> 8) & 255); }
  function u32(arr, n) { arr.push(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255); }

  function zipStore(entries) {
    const enc = new TextEncoder();
    const parts = [];
    const central = [];
    let offset = 0;
    const now = dosDateTime();
    for (const entry of entries) {
      const nameBytes = enc.encode(entry.name);
      const data = entry.data instanceof Uint8Array ? entry.data : enc.encode(String(entry.data || ''));
      const crc = crc32(data);
      const local = [];
      u32(local, 0x04034b50); u16(local, 20); u16(local, 0); u16(local, 0); u16(local, now.time); u16(local, now.day); u32(local, crc); u32(local, data.length); u32(local, data.length); u16(local, nameBytes.length); u16(local, 0);
      parts.push(new Uint8Array(local), nameBytes, data);
      const cent = [];
      u32(cent, 0x02014b50); u16(cent, 20); u16(cent, 20); u16(cent, 0); u16(cent, 0); u16(cent, now.time); u16(cent, now.day); u32(cent, crc); u32(cent, data.length); u32(cent, data.length); u16(cent, nameBytes.length); u16(cent, 0); u16(cent, 0); u16(cent, 0); u16(cent, 0); u32(cent, 0); u32(cent, offset);
      central.push(new Uint8Array(cent), nameBytes);
      offset += local.length + nameBytes.length + data.length;
    }
    const centralOffset = offset;
    const centralSize = central.reduce((sum, p) => sum + p.length, 0);
    const end = [];
    u32(end, 0x06054b50); u16(end, 0); u16(end, 0); u16(end, entries.length); u16(end, entries.length); u32(end, centralSize); u32(end, centralOffset); u16(end, 0);
    return new Blob([...parts, ...central, new Uint8Array(end)], { type: 'application/vnd.oasis.opendocument.text' });
  }

  async function createFindingsOdt({ label, notes, pngBlob }) {
    const pngBytes = new Uint8Array(await pngBlob.arrayBuffer());
    const devices = Array.from(state.devicesOfInterest).map(host => {
      const meta = state.hostIndex.get(host) || { host };
      return { host, display: hostDisplay(host), type: deviceShapeLabel(meta.deviceType || inferDeviceType(meta)) };
    });
    const filters = state.filters && state.filters.active ? JSON.stringify({ text: state.filters.textTokens, host: state.filters.hostTokens, src: state.filters.srcTokens, dst: state.filters.dstTokens, ports: state.filters.portRanges, protocols: Array.from(state.filters.protocols) }) : 'none';
    const deviceXml = devices.length ? devices.map(d => `<text:list-item><text:p text:style-name="P1">${escapeXml(d.display)} — ${escapeXml(d.type)} — ${escapeXml(d.host)}</text:p></text:list-item>`).join('') : '<text:list-item><text:p text:style-name="P1">No devices were marked.</text:p></text:list-item>';
    const paragraphs = String(notes || '').split(/\r?\n/).map(line => `<text:p text:style-name="P1">${escapeXml(line || ' ')}</text:p>`).join('');
    const content = `<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" office:version="1.2"><office:automatic-styles><style:style style:name="P1" style:family="paragraph"><style:paragraph-properties fo:margin-bottom="0.12in"/></style:style><style:style style:name="H1" style:family="paragraph"><style:text-properties fo:font-size="20pt" fo:font-weight="bold"/></style:style><style:style style:name="fr1" style:family="graphic"><style:graphic-properties style:wrap="none"/></style:style></office:automatic-styles><office:body><office:text><text:h text:style-name="H1" text:outline-level="1">Export Findings</text:h><text:p text:style-name="P1"><text:span text:style-name="H1">${escapeXml(label)}</text:span></text:p><text:p text:style-name="P1">Capture time: ${escapeXml(formatDuration(state.currentTime))}</text:p><text:p text:style-name="P1">Playback window: ${escapeXml(state.lastView ? formatDuration(state.lastView.start) + ' - ' + formatDuration(state.lastView.end) : '--')}</text:p><text:p text:style-name="P1">Theme: ${escapeXml(state.theme)} | Active filters: ${escapeXml(filters)}</text:p><draw:frame draw:style-name="fr1" draw:name="Network display" text:anchor-type="paragraph" svg:width="7.2in" svg:height="4.6in"><draw:image xlink:href="Pictures/finding.png" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/></draw:frame><text:h text:style-name="H1" text:outline-level="2">Analyst notes</text:h>${paragraphs || '<text:p text:style-name="P1">No notes entered.</text:p>'}<text:h text:style-name="H1" text:outline-level="2">Devices of Interest in Findings</text:h><text:list>${deviceXml}</text:list></office:text></office:body></office:document-content>`;
    const styles = `<?xml version="1.0" encoding="UTF-8"?><office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" office:version="1.2"><office:styles><style:default-style style:family="paragraph"><style:text-properties fo:font-family="Arial" fo:font-size="11pt"/></style:default-style></office:styles></office:document-styles>`;
    const meta = `<?xml version="1.0" encoding="UTF-8"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" office:version="1.2"><office:meta><meta:generator>PCAP Visualizer Export Findings</meta:generator><meta:creation-date>${new Date().toISOString()}</meta:creation-date></office:meta></office:document-meta>`;
    const manifest = `<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="Pictures/finding.png" manifest:media-type="image/png"/></manifest:manifest>`;
    return zipStore([
      { name: 'mimetype', data: 'application/vnd.oasis.opendocument.text' },
      { name: 'content.xml', data: content },
      { name: 'styles.xml', data: styles },
      { name: 'meta.xml', data: meta },
      { name: 'META-INF/manifest.xml', data: manifest },
      { name: 'Pictures/finding.png', data: pngBytes }
    ]);
  }

  async function submitFindingsExport(event) {
    event.preventDefault();
    if (!state.capture) return;
    const label = els.findingLabel.value.trim() || 'Network finding';
    const notes = els.findingNotes.value.trim();
    try {
      els.status.textContent = 'Exporting finding report...';
      const pngBlob = await graphPngBlob();
      const odt = await createFindingsOdt({ label, notes, pngBlob });
      downloadBlob(odt, 'Export-Findings-' + slugify(label) + '.odt');
      closeFindingsModal();
      els.status.textContent = 'Export Findings complete: ODT report generated with embedded PNG network display.';
    } catch (error) {
      alert('Export Findings failed: ' + (error && error.message ? error.message : error));
      els.status.textContent = 'Export Findings failed.';
    }
  }

  function resetView() {
    state.layoutKey = '';
    state.layout.clear();
    state.particles = [];
    resetPanZoom();
    state.needsRender = true;
  }

  function wireEvents() {
    els.fileInput.addEventListener('change', event => loadFile(event.target.files && event.target.files[0]));
    for (const eventName of ['dragenter', 'dragover']) {
      document.addEventListener(eventName, event => { event.preventDefault(); document.body.classList.add('dragging'); });
    }
    for (const eventName of ['dragleave', 'drop']) {
      document.addEventListener(eventName, event => { event.preventDefault(); if (eventName === 'drop') loadFile(event.dataTransfer.files && event.dataTransfer.files[0]); document.body.classList.remove('dragging'); });
    }
    els.playPause.addEventListener('click', () => { if (!state.capture) return; state.playing = !state.playing; if (state.currentTime >= state.duration) setTime(0, true); updatePlaybackButton(); });
    els.back10.addEventListener('click', () => setTime(state.currentTime - 10, true));
    els.forward10.addEventListener('click', () => setTime(state.currentTime + 10, true));
    els.backStep.addEventListener('click', () => setTime(state.currentTime - state.windowSec, true));
    els.forwardStep.addEventListener('click', () => setTime(state.currentTime + state.windowSec, true));
    els.prevMatch.addEventListener('click', () => jumpMatch(-1));
    els.nextMatch.addEventListener('click', () => jumpMatch(1));
    els.themeSelect.addEventListener('change', () => applyTheme(els.themeSelect.value));
    els.speedSelect.addEventListener('change', () => { state.speed = Number(els.speedSelect.value) || 1; });
    els.windowSelect.addEventListener('change', () => { state.windowSec = Number(els.windowSelect.value) || 1; state.needsRender = true; });
    els.maxNodes.addEventListener('input', () => { state.maxNodes = Number(els.maxNodes.value) || 160; els.maxNodesLabel.textContent = String(state.maxNodes); state.layoutKey = ''; state.needsRender = true; });
    els.hostSpacing.addEventListener('input', () => { state.hostSpacing = Number(els.hostSpacing.value) || 1.45; els.hostSpacingLabel.textContent = state.hostSpacing.toFixed(2).replace(/\.00$/, '') + 'x'; state.layoutKey = ''; state.needsRender = true; });
    els.showAll.addEventListener('change', () => { state.showAll = els.showAll.checked; state.layoutKey = ''; state.needsRender = true; });
    els.preferDns.addEventListener('change', () => { state.preferDns = els.preferDns.checked; state.needsRender = true; renderDnsPanel(state.dns); updateFilterStatus(); });
    els.showIpUnderName.addEventListener('change', () => { state.showIpUnderName = els.showIpUnderName.checked; state.needsRender = true; });
    els.timeline.addEventListener('input', () => setTime(Number(els.timeline.value), true));
    els.snapshot.addEventListener('click', saveSvg);
    els.savePng.addEventListener('click', savePng);
    els.exportFindings.addEventListener('click', openFindingsModal);
    els.cancelFindings.addEventListener('click', closeFindingsModal);
    els.findingsForm.addEventListener('submit', submitFindingsExport);
    els.findingsModal.addEventListener('click', event => { if (event.target === els.findingsModal) closeFindingsModal(); });
    els.zoomIn.addEventListener('click', () => zoomGraph(1.22));
    els.zoomOut.addEventListener('click', () => zoomGraph(1 / 1.22));
    els.zoomReset.addEventListener('click', resetPanZoom);
    els.zoomFit.addEventListener('click', fitVisibleGraph);
    els.panUp.addEventListener('click', () => panGraph(0, 64));
    els.panDown.addEventListener('click', () => panGraph(0, -64));
    els.panLeft.addEventListener('click', () => panGraph(64, 0));
    els.panRight.addEventListener('click', () => panGraph(-64, 0));
    els.graphSvg.addEventListener('wheel', event => { event.preventDefault(); const rect = els.graphSvg.getBoundingClientRect(); zoomGraph(event.deltaY < 0 ? 1.12 : 1 / 1.12, { x: event.clientX - rect.left, y: event.clientY - rect.top }); }, { passive: false });
    els.graphSvg.addEventListener('pointerdown', event => { if (event.button !== 0 || event.target.closest('.node')) return; state.isPanning = true; state.panStart = { x: event.clientX, y: event.clientY, px: state.panZoom.x, py: state.panZoom.y }; els.graphSvg.setPointerCapture(event.pointerId); });
    els.graphSvg.addEventListener('pointermove', event => { if (!state.isPanning || !state.panStart) return; setPanZoom({ x: state.panStart.px + event.clientX - state.panStart.x, y: state.panStart.py + event.clientY - state.panStart.y, scale: state.panZoom.scale }); });
    els.graphSvg.addEventListener('pointerup', event => { state.isPanning = false; state.panStart = null; try { els.graphSvg.releasePointerCapture(event.pointerId); } catch {} });
    els.resetView.addEventListener('click', resetView);
    for (const el of [els.searchText, els.hostFilter, els.srcFilter, els.dstFilter, els.portFilter]) el.addEventListener('input', () => applyFilters(true));
    els.clearFilters.addEventListener('click', clearFilters);
    els.hostSpacingLabel.textContent = state.hostSpacing.toFixed(2).replace(/\.00$/, '') + 'x';
    els.protocolChips.addEventListener('click', event => {
      const btn = event.target.closest('.chip');
      if (!btn) return;
      const value = btn.getAttribute('data-protocol');
      if (!value) return;
      if (state.selectedProtocols.has(value)) { state.selectedProtocols.delete(value); btn.classList.remove('active'); }
      else { state.selectedProtocols.add(value); btn.classList.add('active'); }
      applyFilters(false);
    });
    els.nodesLayer.addEventListener('click', event => {
      const node = event.target.closest('.node');
      if (!node) return;
      const host = node.getAttribute('data-host');
      state.selectedHost = state.selectedHost === host ? null : host;
      state.needsRender = true;
      renderHostPanel(state.selectedHost, state.lastView);
    });
    window.addEventListener('resize', () => { state.layoutKey = ''; state.needsRender = true; });
    document.addEventListener('keydown', event => {
      if (event.target && ['INPUT', 'TEXTAREA'].includes(event.target.tagName)) return;
      if (event.code === 'Space') { event.preventDefault(); els.playPause.click(); }
      else if (event.key === 'ArrowLeft') setTime(state.currentTime - (event.shiftKey ? 10 : state.windowSec), true);
      else if (event.key === 'ArrowRight') setTime(state.currentTime + (event.shiftKey ? 10 : state.windowSec), true);
      else if (event.key.toLowerCase() === 'n') jumpMatch(1);
      else if (event.key.toLowerCase() === 'p') jumpMatch(-1);
      else if (event.key === '+') zoomGraph(1.22);
      else if (event.key === '-') zoomGraph(1 / 1.22);
      else if (event.key === 'Escape' && !els.findingsModal.classList.contains('hidden')) closeFindingsModal();
    });
  }

  wireEvents();
  updateControlsEnabled(false);
  state.speed = Number(els.speedSelect.value) || 30;
  state.windowSec = Number(els.windowSelect.value) || 1;
  applyTheme(els.themeSelect ? els.themeSelect.value : 'cyber');
  state.maxNodes = Number(els.maxNodes.value) || 160;
  state.hostSpacing = Number(els.hostSpacing.value) || 1.45;
  els.maxNodesLabel.textContent = String(state.maxNodes);
  els.hostSpacingLabel.textContent = state.hostSpacing.toFixed(2).replace(/\.00$/, '') + 'x';
  drawGrid();
  applyGraphTransform();
  requestAnimationFrame(animationLoop);
})();
