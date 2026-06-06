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
    maxNodes: document.getElementById('maxNodes'),
    maxNodesLabel: document.getElementById('maxNodesLabel'),
    showAll: document.getElementById('showAll'),
    preferDns: document.getElementById('preferDns'),
    showIpUnderName: document.getElementById('showIpUnderName'),
    timeline: document.getElementById('timeline'),
    currentTime: document.getElementById('currentTime'),
    durationTime: document.getElementById('durationTime'),
    snapshot: document.getElementById('snapshot'),
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
    maxNodes: 160,
    showAll: false,
    preferDns: true,
    showIpUnderName: true,
    selectedHost: null,
    particles: [],
    dimensions: { w: 900, h: 640 },
    lastFrameAt: 0,
    fpsFrames: 0,
    fpsStarted: performance.now(),
    lastPanelAt: 0,
    layoutKey: '',
    layout: new Map(),
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
    state.particles = [];
    state.layoutKey = '';
    state.layout.clear();
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
    state.filteredHostStats = state.summary.hostStats || [];
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
    els.status.textContent = 'Loaded ' + fmtCount(state.summary.packetsDecoded) + ' decoded packets, ' + fmtCount(state.summary.hostCount) + ' hosts, ' + fmtCount(state.summary.dnsPacketCount) + ' DNS-family packets, ' + fmtCount(state.summary.dnsResolutionCount) + ' resolved name entries.';
  }

  function updateControlsEnabled(enabled) {
    for (const el of [els.playPause, els.back10, els.backStep, els.forwardStep, els.forward10, els.prevMatch, els.nextMatch, els.timeline, els.snapshot, els.resetView, els.clearFilters]) {
      el.disabled = !enabled;
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

  function buildHostStatsFromPackets(packets) {
    if (!state.filters || !state.filters.active) return state.summary ? (state.summary.hostStats || []) : [];
    const map = new Map();
    function ensure(host) {
      if (!map.has(host)) {
        const meta = state.hostIndex.get(host) || { host, label: hostLabel(host), names: [], className: classifyHost(host) };
        map.set(host, { host, label: meta.label || hostLabel(host), names: meta.names || [], className: meta.className || classifyHost(host), sentPackets: 0, recvPackets: 0, sentBytes: 0, recvBytes: 0, totalPackets: 0, totalBytes: 0 });
      }
      return map.get(host);
    }
    for (const p of packets) {
      const s = ensure(p.src);
      const d = ensure(p.dst);
      s.sentPackets += 1; s.sentBytes += p.bytes || 0; s.totalPackets += 1; s.totalBytes += p.bytes || 0;
      d.recvPackets += 1; d.recvBytes += p.bytes || 0; d.totalPackets += 1; d.totalBytes += p.bytes || 0;
    }
    return Array.from(map.values()).sort((a, b) => b.totalPackets - a.totalPackets || a.host.localeCompare(b.host));
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
        totalBytes: meta.totalBytes || h.bytes
      });
    }
    if (state.showAll) {
      for (const meta of state.filteredHostStats || []) {
        if (nodeMap.size >= state.maxNodes) break;
        if (!nodeMap.has(meta.host)) nodeMap.set(meta.host, {
          host: meta.host,
          label: meta.label || hostLabel(meta.host),
          className: meta.className || classifyHost(meta.host),
          active: false,
          windowPackets: 0,
          windowBytes: 0,
          totalPackets: meta.totalPackets || 0,
          totalBytes: meta.totalBytes || 0
        });
      }
    }
    let nodes = Array.from(nodeMap.values());
    nodes.sort((a, b) => Number(b.active) - Number(a.active) || b.windowPackets - a.windowPackets || b.totalPackets - a.totalPackets || a.host.localeCompare(b.host));
    nodes = nodes.slice(0, state.maxNodes);
    return nodes;
  }

  function computeLayout(nodes) {
    const w = state.dimensions.w;
    const h = state.dimensions.h;
    const key = w + 'x' + h + '|' + nodes.map(n => n.host + ':' + (n.active ? '1' : '0')).sort().join('|');
    if (key === state.layoutKey && state.layout.size) return state.layout;
    state.layoutKey = key;
    const cx = w / 2;
    const cy = h / 2;
    const minSide = Math.min(w, h);
    const maxR = Math.max(100, minSide / 2 - 72);
    const groups = { local: [], remote: [], mac: [], multicast: [], broadcast: [], other: [] };
    for (const n of nodes) (groups[n.className] || groups.other).push(n);
    const layout = new Map();
    const specs = {
      local: { r: 0.34, phase: 0.00 },
      mac: { r: 0.50, phase: 0.28 },
      remote: { r: 0.74, phase: 0.11 },
      multicast: { r: 0.88, phase: 0.45 },
      broadcast: { r: 0.92, phase: 0.72 },
      other: { r: 0.62, phase: 0.19 }
    };
    for (const [cls, list] of Object.entries(groups)) {
      list.sort((a, b) => hashString(a.host) - hashString(b.host));
      const spec = specs[cls] || specs.other;
      const rings = Math.max(1, Math.ceil(list.length / 42));
      list.forEach((node, idx) => {
        const ring = idx % rings;
        const posInRing = Math.floor(idx / rings);
        const countInRing = Math.ceil(list.length / rings);
        const angle = (Math.PI * 2 * (posInRing / Math.max(1, countInRing))) + spec.phase * Math.PI * 2 + (ring * 0.19);
        const jitter = ((hashString(node.host + ':r') % 1000) / 1000 - 0.5) * 0.08;
        const radius = maxR * Math.min(0.96, Math.max(0.18, spec.r + jitter + ring * 0.045));
        layout.set(node.host, { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius, r: nodeRadius(node), node });
      });
    }

    const arr = Array.from(layout.values());
    const minDist = Math.max(26, Math.min(46, minSide / 18));
    for (let iter = 0; iter < 18; iter++) {
      for (let i = 0; i < arr.length; i++) {
        for (let j = i + 1; j < arr.length; j++) {
          const a = arr[i], b = arr[j];
          let dx = b.x - a.x, dy = b.y - a.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 0.01) { dx = 0.1; dy = 0.1; d2 = 0.02; }
          const d = Math.sqrt(d2);
          const wanted = minDist + a.r * 0.55 + b.r * 0.55;
          if (d < wanted) {
            const push = (wanted - d) * 0.22;
            const ux = dx / d, uy = dy / d;
            a.x -= ux * push; a.y -= uy * push;
            b.x += ux * push; b.y += uy * push;
          }
        }
      }
      for (const p of arr) {
        p.x = Math.max(34, Math.min(w - 34, p.x));
        p.y = Math.max(34, Math.min(h - 44, p.y));
      }
    }
    state.layout = layout;
    return layout;
  }

  function nodeRadius(node) {
    const score = (node.windowPackets || 0) * 4 + Math.log10((node.totalPackets || 1) + 1) * 8;
    return Math.max(6, Math.min(22, 6 + score));
  }

  function updateDimensions() {
    const rect = els.graphShell.getBoundingClientRect();
    const w = Math.max(640, Math.floor(rect.width));
    const h = Math.max(420, Math.floor(rect.height));
    if (w !== state.dimensions.w || h !== state.dimensions.h) {
      state.dimensions = { w, h };
      els.graphSvg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
      drawGrid();
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
      const cls = 'node ' + (n.className || 'remote') + (n.active ? '' : ' inactive') + (state.selectedHost === n.host ? ' selected' : '');
      const title = hostDisplay(n.host) + '\nPackets now: ' + n.windowPackets + '\nTotal packets: ' + n.totalPackets;
      nodeHtml += '<g class="' + cls + '" data-host="' + escapeAttr(n.host) + '"><title>' + escapeHtml(title) + '</title>';
      if (state.selectedHost === n.host) nodeHtml += '<circle class="halo" cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="' + (p.r + 9).toFixed(1) + '"></circle>';
      nodeHtml += '<circle cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="' + p.r.toFixed(1) + '"></circle>';
      nodeHtml += '<text x="' + p.x.toFixed(1) + '" y="' + (p.y + p.r + 14).toFixed(1) + '" text-anchor="middle">' + escapeHtml(shortenHost(label, 28)) + '</text>';
      if (sub) nodeHtml += '<text class="subtext" x="' + p.x.toFixed(1) + '" y="' + (p.y + p.r + 27).toFixed(1) + '" text-anchor="middle">' + escapeHtml(shortenHost(sub, 24)) + '</text>';
      nodeHtml += '</g>';
    }
    els.nodesLayer.innerHTML = nodeHtml;
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
      els.hostPanel.innerHTML = '<div class="kv"><span class="k">Tip</span><span class="v">Click a node to pin host details here. DNS aliases are searchable.</span></div>';
      return;
    }
    const meta = state.hostIndex.get(host) || { host, label: hostLabel(host), names: [], className: classifyHost(host) };
    const current = view && view.hosts ? view.hosts.get(host) : null;
    const names = (meta.names || []).slice(0, 12).map(n => '<span class="pill">' + escapeHtml(shortenHost(n, 34)) + '</span>').join(' ');
    els.hostPanel.innerHTML = [
      kv('Display', hostDisplay(host)),
      kv('Address', host),
      kv('Class', meta.className || classifyHost(host)),
      kv('Total packets', fmtCount(meta.totalPackets || 0)),
      kv('Total bytes', fmtBytes(meta.totalBytes || 0)),
      kv('Sent / recv', fmtCount(meta.sentPackets || 0) + ' / ' + fmtCount(meta.recvPackets || 0)),
      kv('Now sent / recv', current ? (fmtCount(current.sent) + ' / ' + fmtCount(current.recv)) : '0 / 0'),
      '<div class="chip-note">Known DNS names</div><div class="pill-wrap">' + (names || '<span class="muted">No DNS alias decoded for this host</span>') + '</div>',
      '<button class="small-button" id="filterThisHost" type="button">Filter this host</button>'
    ].join('');
    const btn = document.getElementById('filterThisHost');
    if (btn) btn.onclick = () => { els.hostFilter.value = hostDisplay(host, false); applyFilters(false); };
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

  function saveSvg() {
    const clone = els.graphSvg.cloneNode(true);
    clone.setAttribute('xmlns', SVG_NS);
    const source = '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(clone);
    const blob = new Blob([source], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'pcapng-traffic-movie-' + Math.round(state.currentTime) + 's.svg';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function resetView() {
    state.layoutKey = '';
    state.layout.clear();
    state.particles = [];
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
    els.speedSelect.addEventListener('change', () => { state.speed = Number(els.speedSelect.value) || 1; });
    els.windowSelect.addEventListener('change', () => { state.windowSec = Number(els.windowSelect.value) || 1; state.needsRender = true; });
    els.maxNodes.addEventListener('input', () => { state.maxNodes = Number(els.maxNodes.value) || 160; els.maxNodesLabel.textContent = String(state.maxNodes); state.layoutKey = ''; state.needsRender = true; });
    els.showAll.addEventListener('change', () => { state.showAll = els.showAll.checked; state.layoutKey = ''; state.needsRender = true; });
    els.preferDns.addEventListener('change', () => { state.preferDns = els.preferDns.checked; state.needsRender = true; renderDnsPanel(state.dns); updateFilterStatus(); });
    els.showIpUnderName.addEventListener('change', () => { state.showIpUnderName = els.showIpUnderName.checked; state.needsRender = true; });
    els.timeline.addEventListener('input', () => setTime(Number(els.timeline.value), true));
    els.snapshot.addEventListener('click', saveSvg);
    els.resetView.addEventListener('click', resetView);
    for (const el of [els.searchText, els.hostFilter, els.srcFilter, els.dstFilter, els.portFilter]) el.addEventListener('input', () => applyFilters(true));
    els.clearFilters.addEventListener('click', clearFilters);
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
    });
  }

  wireEvents();
  updateControlsEnabled(false);
  state.speed = Number(els.speedSelect.value) || 30;
  state.windowSec = Number(els.windowSelect.value) || 1;
  state.maxNodes = Number(els.maxNodes.value) || 160;
  els.maxNodesLabel.textContent = String(state.maxNodes);
  renderEmptyGraph();
  requestAnimationFrame(animationLoop);
})();
