/*
  PCAPNG Traffic Movie v2 parser core
  Standalone browser/worker compatible parser for PCAPNG and classic PCAP.
  Decodes Ethernet, raw IPv4/IPv6, Linux cooked captures, TCP, UDP, ICMP,
  ARP, DNS, mDNS and LLMNR for host-flow visualization and filtering.
*/

const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_PB_OBSOLETE = 0x00000002;
const BLOCK_SPB = 0x00000003;
const BLOCK_NRB = 0x00000004;
const BLOCK_ISB = 0x00000005;
const BLOCK_EPB = 0x00000006;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;
const TWO_32 = 4294967296;

const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW = 101;
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_IPV4 = 228;
const LINKTYPE_IPV6 = 229;
const LINKTYPE_LINUX_SLL2 = 276;

const DNS_PORTS = new Set([53, 5353, 5355]);
const MAX_DNS_RECORDS = 250;
const textDecoder = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8') : null;

function align4(n) { return (n + 3) & ~3; }

function bump(map, key, inc = 1) {
  key = String(key || 'unknown');
  map[key] = (map[key] || 0) + inc;
}

function sortedEntriesFromMapObj(obj) {
  return Object.entries(obj).sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
}

function blockName(type) {
  switch (type) {
    case BLOCK_SHB: return 'SHB';
    case BLOCK_IDB: return 'IDB';
    case BLOCK_EPB: return 'EPB';
    case BLOCK_SPB: return 'SPB';
    case BLOCK_NRB: return 'NRB';
    case BLOCK_ISB: return 'ISB';
    case BLOCK_PB_OBSOLETE: return 'PB_OBSOLETE';
    default: return '0x' + type.toString(16).padStart(8, '0');
  }
}

function safeDecode(bytes, start = 0, length = bytes.length - start) {
  const end = Math.max(start, Math.min(bytes.length, start + length));
  let trimmedEnd = end;
  while (trimmedEnd > start && bytes[trimmedEnd - 1] === 0) trimmedEnd -= 1;
  const slice = bytes.subarray(start, trimmedEnd);
  if (!textDecoder) {
    let s = '';
    for (const b of slice) s += String.fromCharCode(b);
    return s;
  }
  try { return textDecoder.decode(slice); }
  catch { return Array.from(slice).map(b => String.fromCharCode(b)).join(''); }
}

function decodeText(view, start, length) {
  const bytes = new Uint8Array(view.buffer, view.byteOffset + start, length);
  return safeDecode(bytes);
}

function parseOptions(view, start, end, little) {
  const options = [];
  let off = start;
  while (off + 4 <= end) {
    const code = view.getUint16(off, little);
    const length = view.getUint16(off + 2, little);
    off += 4;
    if (code === 0) break;
    if (off + length > end) break;
    options.push({ code, start: off, length });
    off += align4(length);
  }
  return options;
}

function parseInterfaceOptions(view, start, end, little) {
  const opts = parseOptions(view, start, end, little);
  const result = { tsresol: 1e-6, tsoffset: 0, name: '', description: '', comment: '' };
  for (const opt of opts) {
    if (opt.code === 9 && opt.length >= 1) {
      const v = view.getUint8(opt.start);
      result.tsresol = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v);
    } else if (opt.code === 14 && opt.length >= 8) {
      if (typeof view.getBigInt64 === 'function') {
        result.tsoffset = Number(view.getBigInt64(opt.start, little));
      } else {
        const lo = view.getUint32(opt.start, little);
        const hi = view.getInt32(opt.start + 4, little);
        result.tsoffset = hi * TWO_32 + lo;
      }
    } else if (opt.code === 2) {
      result.name = decodeText(view, opt.start, opt.length);
    } else if (opt.code === 3) {
      result.description = decodeText(view, opt.start, opt.length);
    } else if (opt.code === 1) {
      result.comment = decodeText(view, opt.start, opt.length);
    }
  }
  return result;
}

function formatMac(bytes, off = 0) {
  if (off + 6 > bytes.length) return '';
  const parts = [];
  for (let i = 0; i < 6; i++) parts.push(bytes[off + i].toString(16).padStart(2, '0'));
  return parts.join(':');
}

function formatIPv4(bytes, off = 0) {
  if (off + 4 > bytes.length) return '';
  return bytes[off] + '.' + bytes[off + 1] + '.' + bytes[off + 2] + '.' + bytes[off + 3];
}

function formatIPv6(bytes, off = 0) {
  if (off + 16 > bytes.length) return '';
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(((bytes[off + i * 2] << 8) | bytes[off + i * 2 + 1]).toString(16));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < groups.length;) {
    if (groups[i] !== '0') { i += 1; continue; }
    let j = i;
    while (j < groups.length && groups[j] === '0') j += 1;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  if (bestLen < 2) return groups.join(':');
  const left = groups.slice(0, bestStart).join(':');
  const right = groups.slice(bestStart + bestLen).join(':');
  if (!left && !right) return '::';
  if (!left) return '::' + right;
  if (!right) return left + '::';
  return left + '::' + right;
}

function u16be(bytes, off) {
  if (off + 2 > bytes.length) return 0;
  return (bytes[off] << 8) | bytes[off + 1];
}

function u32be(bytes, off) {
  if (off + 4 > bytes.length) return 0;
  return ((bytes[off] << 24) >>> 0) + (bytes[off + 1] << 16) + (bytes[off + 2] << 8) + bytes[off + 3];
}

function cleanDnsName(name) {
  if (!name) return '';
  let s = String(name).replace(/\0/g, '').trim();
  if (s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

function dnsTypeName(type) {
  switch (type) {
    case 1: return 'A';
    case 2: return 'NS';
    case 5: return 'CNAME';
    case 6: return 'SOA';
    case 12: return 'PTR';
    case 15: return 'MX';
    case 16: return 'TXT';
    case 28: return 'AAAA';
    case 33: return 'SRV';
    case 41: return 'OPT';
    case 65: return 'HTTPS';
    default: return 'TYPE' + type;
  }
}

function readDnsName(bytes, off, msgStart, msgEnd, depth = 0) {
  const labels = [];
  let jumped = false;
  let next = off;
  let ok = true;
  let guard = 0;
  while (off < msgEnd && guard++ < 128) {
    const len = bytes[off];
    if (len === 0) {
      off += 1;
      if (!jumped) next = off;
      return { name: cleanDnsName(labels.join('.')), next, ok };
    }
    const tag = len & 0xc0;
    if (tag === 0xc0) {
      if (off + 1 >= msgEnd) return { name: cleanDnsName(labels.join('.')), next: jumped ? next : msgEnd, ok: false };
      const ptr = ((len & 0x3f) << 8) | bytes[off + 1];
      if (!jumped) next = off + 2;
      off = msgStart + ptr;
      jumped = true;
      if (off < msgStart || off >= msgEnd || depth > 20) return { name: cleanDnsName(labels.join('.')), next, ok: false };
      depth += 1;
      continue;
    }
    if (tag !== 0x00) {
      ok = false;
      if (!jumped) next = off + 1;
      break;
    }
    off += 1;
    if (off + len > msgEnd) {
      ok = false;
      if (!jumped) next = msgEnd;
      break;
    }
    let label = safeDecode(bytes, off, len)
      .replace(/[\x00-\x1f\x7f]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (!label) label = '_';
    labels.push(label);
    off += len;
    if (!jumped) next = off;
  }
  return { name: cleanDnsName(labels.join('.')), next: jumped ? next : Math.min(off + 1, msgEnd), ok: false };
}

function readDnsRecord(bytes, off, msgStart, msgEnd) {
  const nameRead = readDnsName(bytes, off, msgStart, msgEnd);
  off = nameRead.next;
  if (off + 10 > msgEnd) return { record: null, next: msgEnd };
  const type = u16be(bytes, off);
  const klass = u16be(bytes, off + 2);
  const ttl = u32be(bytes, off + 4);
  const rdlen = u16be(bytes, off + 8);
  const rdataOff = off + 10;
  const next = rdataOff + rdlen;
  if (next > msgEnd) return { record: null, next: msgEnd };
  let data = '';
  let address = '';
  if (type === 1 && rdlen === 4) {
    address = formatIPv4(bytes, rdataOff);
    data = address;
  } else if (type === 28 && rdlen === 16) {
    address = formatIPv6(bytes, rdataOff);
    data = address;
  } else if (type === 2 || type === 5 || type === 12) {
    data = readDnsName(bytes, rdataOff, msgStart, msgEnd).name;
  } else if (type === 15 && rdlen >= 3) {
    const pref = u16be(bytes, rdataOff);
    const ex = readDnsName(bytes, rdataOff + 2, msgStart, msgEnd).name;
    data = pref + ' ' + ex;
  } else if (type === 33 && rdlen >= 7) {
    const priority = u16be(bytes, rdataOff);
    const weight = u16be(bytes, rdataOff + 2);
    const port = u16be(bytes, rdataOff + 4);
    const target = readDnsName(bytes, rdataOff + 6, msgStart, msgEnd).name;
    data = priority + ' ' + weight + ' ' + port + ' ' + target;
  } else if (type === 16) {
    const parts = [];
    let p = rdataOff;
    while (p < next) {
      const l = bytes[p];
      p += 1;
      if (p + l > next) break;
      parts.push(safeDecode(bytes, p, l));
      p += l;
    }
    data = parts.join(' ');
  } else if (type === 65 && rdlen >= 3) {
    const priority = u16be(bytes, rdataOff);
    const target = readDnsName(bytes, rdataOff + 2, msgStart, msgEnd).name;
    data = priority + ' ' + target;
  } else {
    data = rdlen ? '[' + rdlen + ' bytes]' : '';
  }
  return {
    record: {
      name: cleanDnsName(nameRead.name),
      type,
      typeName: dnsTypeName(type),
      class: klass,
      ttl,
      data: cleanDnsName(data),
      address
    },
    next
  };
}

function parseDnsMessage(bytes, off, length, flavor = 'DNS') {
  const msgStart = off;
  const msgEnd = Math.min(bytes.length, off + length);
  if (msgEnd - msgStart < 12) return null;
  const id = u16be(bytes, off);
  const flags = u16be(bytes, off + 2);
  const qd = u16be(bytes, off + 4);
  const an = u16be(bytes, off + 6);
  const ns = u16be(bytes, off + 8);
  const ar = u16be(bytes, off + 10);
  const totalRecords = qd + an + ns + ar;
  if (totalRecords > MAX_DNS_RECORDS) return null;
  off += 12;
  const questions = [];
  const answers = [];
  const authorities = [];
  const additionals = [];
  const names = new Set();
  const addresses = [];
  const cnames = [];
  const ptrs = [];

  for (let i = 0; i < qd && off < msgEnd; i++) {
    const nr = readDnsName(bytes, off, msgStart, msgEnd);
    off = nr.next;
    if (off + 4 > msgEnd) break;
    const qtype = u16be(bytes, off);
    const qclass = u16be(bytes, off + 2);
    off += 4;
    const qname = cleanDnsName(nr.name);
    if (qname) names.add(qname);
    questions.push({ name: qname, type: qtype, typeName: dnsTypeName(qtype), class: qclass });
  }

  function readRecords(count, dest) {
    for (let i = 0; i < count && off < msgEnd; i++) {
      const rr = readDnsRecord(bytes, off, msgStart, msgEnd);
      off = rr.next;
      if (!rr.record) break;
      const rec = rr.record;
      dest.push(rec);
      if (rec.name) names.add(rec.name);
      if (rec.data && /[a-zA-Z]/.test(rec.data) && !rec.data.startsWith('[')) names.add(rec.data);
      if ((rec.type === 1 || rec.type === 28) && rec.address && rec.name) {
        addresses.push({ name: rec.name, address: rec.address, type: rec.typeName, ttl: rec.ttl });
      } else if (rec.type === 5 && rec.name && rec.data) {
        cnames.push({ alias: rec.name, canonical: rec.data, ttl: rec.ttl });
      } else if (rec.type === 12 && rec.name && rec.data) {
        ptrs.push({ ptr: rec.name, name: rec.data, ttl: rec.ttl });
      }
    }
  }

  readRecords(an, answers);
  readRecords(ns, authorities);
  readRecords(ar, additionals);

  let label = flavor;
  const isResponse = Boolean(flags & 0x8000);
  if (questions.length) label += ' Q ' + questions.slice(0, 3).map(q => q.name || q.typeName).join(', ');
  const answerNames = answers.concat(additionals).filter(r => r.type === 1 || r.type === 28 || r.type === 12 || r.type === 5).slice(0, 3)
    .map(r => r.name && r.data ? r.name + ' -> ' + r.data : (r.name || r.data || r.typeName));
  if (answerNames.length) label = flavor + ' ' + answerNames.join(', ');

  return {
    id,
    flags,
    qr: isResponse ? 'response' : 'query',
    opcode: (flags >> 11) & 0x0f,
    rcode: flags & 0x0f,
    questionCount: qd,
    answerCount: an,
    authorityCount: ns,
    additionalCount: ar,
    questions,
    answers,
    authorities,
    additionals,
    names: Array.from(names).slice(0, 200),
    addresses,
    cnames,
    ptrs,
    label
  };
}

function serviceForPort(protocol, sport, dport) {
  const ports = [dport, sport].filter(p => Number.isFinite(p));
  if (protocol === 'UDP' && (sport === 443 || dport === 443)) return 'QUIC';
  for (const port of ports) {
    switch (port) {
      case 20: return 'FTP-DATA';
      case 21: return 'FTP';
      case 22: return 'SSH';
      case 23: return 'TELNET';
      case 25: return 'SMTP';
      case 53: return 'DNS';
      case 67: case 68: return 'DHCP';
      case 80: return 'HTTP';
      case 110: return 'POP3';
      case 123: return 'NTP';
      case 137: case 138: case 139: return 'NETBIOS';
      case 143: return 'IMAP';
      case 161: case 162: return 'SNMP';
      case 389: return 'LDAP';
      case 443: return 'HTTPS';
      case 445: return 'SMB';
      case 465: return 'SMTPS';
      case 500: return 'IKE';
      case 587: return 'SUBMISSION';
      case 993: return 'IMAPS';
      case 995: return 'POP3S';
      case 1900: return 'SSDP';
      case 3389: return 'RDP';
      case 5353: return 'MDNS';
      case 5355: return 'LLMNR';
      default: break;
    }
  }
  return ports.length ? protocol + '/' + ports[0] : protocol;
}

function protocolNameIPv4(n) {
  switch (n) {
    case 1: return 'ICMP';
    case 2: return 'IGMP';
    case 6: return 'TCP';
    case 17: return 'UDP';
    case 41: return 'IPv6';
    case 47: return 'GRE';
    case 50: return 'ESP';
    case 51: return 'AH';
    case 89: return 'OSPF';
    case 132: return 'SCTP';
    default: return 'IPv4-' + n;
  }
}

function protocolNameIPv6(n) {
  switch (n) {
    case 6: return 'TCP';
    case 17: return 'UDP';
    case 47: return 'GRE';
    case 50: return 'ESP';
    case 51: return 'AH';
    case 58: return 'ICMPv6';
    case 89: return 'OSPF';
    case 132: return 'SCTP';
    default: return 'IPv6-' + n;
  }
}

function basePacket(src, dst, protocol, length, extra = {}) {
  const sport = Number.isFinite(extra.sport) ? extra.sport : null;
  const dport = Number.isFinite(extra.dport) ? extra.dport : null;
  const service = extra.service || serviceForPort(protocol, sport, dport);
  return {
    src,
    dst,
    protocol,
    service,
    sport,
    dport,
    bytes: Number(extra.origLen || length || 0),
    caplen: Number(extra.caplen || length || 0),
    srcMac: extra.srcMac || '',
    dstMac: extra.dstMac || '',
    ethType: extra.ethType || '',
    detail: extra.detail || '',
    vlan: extra.vlan || null,
    dns: extra.dns || null,
    tcpFlags: extra.tcpFlags || ''
  };
}

function tcpFlagsString(byte) {
  const flags = [];
  if (byte & 0x01) flags.push('FIN');
  if (byte & 0x02) flags.push('SYN');
  if (byte & 0x04) flags.push('RST');
  if (byte & 0x08) flags.push('PSH');
  if (byte & 0x10) flags.push('ACK');
  if (byte & 0x20) flags.push('URG');
  if (byte & 0x40) flags.push('ECE');
  if (byte & 0x80) flags.push('CWR');
  return flags.join(',');
}

function parseIPv4(bytes, off, length, linkMeta = {}) {
  if (off + 20 > length) return null;
  const vihl = bytes[off];
  const version = vihl >> 4;
  const ihl = (vihl & 0x0f) * 4;
  if (version !== 4 || ihl < 20 || off + ihl > length) return null;
  const totalLenField = u16be(bytes, off + 2);
  const totalLen = Math.max(ihl, Math.min(length - off, totalLenField || (length - off)));
  const end = off + totalLen;
  const protocolNumber = bytes[off + 9];
  const protocol = protocolNameIPv4(protocolNumber);
  const src = formatIPv4(bytes, off + 12);
  const dst = formatIPv4(bytes, off + 16);
  const frag = u16be(bytes, off + 6);
  const moreFragments = Boolean(frag & 0x2000);
  const fragmentOffset = frag & 0x1fff;
  const poff = off + ihl;
  let sport = null, dport = null, detail = '', dns = null, service = '', tcpFlags = '';

  if ((protocolNumber === 6 || protocolNumber === 17 || protocolNumber === 132) && fragmentOffset === 0 && poff + 4 <= end) {
    sport = u16be(bytes, poff);
    dport = u16be(bytes, poff + 2);
    detail = sport + ' -> ' + dport;
    if (protocolNumber === 6 && poff + 20 <= end) {
      const tcpHeaderLen = ((bytes[poff + 12] >> 4) & 0x0f) * 4;
      tcpFlags = tcpFlagsString(bytes[poff + 13]);
      detail += tcpFlags ? ' ' + tcpFlags : '';
      const payloadOff = poff + tcpHeaderLen;
      const payloadLen = Math.max(0, end - payloadOff);
      if ((sport === 53 || dport === 53) && payloadLen > 2) {
        const dnsLen = Math.min(payloadLen - 2, u16be(bytes, payloadOff));
        dns = parseDnsMessage(bytes, payloadOff + 2, dnsLen, 'DNS');
      }
    } else if (protocolNumber === 17 && poff + 8 <= end) {
      const udpLen = u16be(bytes, poff + 4);
      const payloadOff = poff + 8;
      const payloadLen = Math.max(0, Math.min(end, poff + (udpLen || (end - poff))) - payloadOff);
      if (DNS_PORTS.has(sport) || DNS_PORTS.has(dport)) {
        const flavor = (sport === 5353 || dport === 5353) ? 'MDNS' : ((sport === 5355 || dport === 5355) ? 'LLMNR' : 'DNS');
        dns = parseDnsMessage(bytes, payloadOff, payloadLen, flavor);
      }
    }
    service = dns ? ((sport === 5353 || dport === 5353) ? 'MDNS' : ((sport === 5355 || dport === 5355) ? 'LLMNR' : 'DNS')) : serviceForPort(protocol, sport, dport);
    if (dns && dns.label) detail = dns.label;
  } else if (protocolNumber === 1 && poff + 2 <= end) {
    detail = 'type ' + bytes[poff] + ' code ' + bytes[poff + 1];
  } else if (moreFragments || fragmentOffset !== 0) {
    detail = 'fragment offset ' + (fragmentOffset * 8);
  }

  return basePacket(src, dst, protocol, linkMeta.origLen || totalLen, {
    ...linkMeta, sport, dport, detail, dns, service, tcpFlags
  });
}

function skipIPv6Extensions(bytes, nextHeader, off, length) {
  let nh = nextHeader;
  let poff = off;
  let hops = 0;
  while (hops < 12) {
    if (nh === 0 || nh === 43 || nh === 60 || nh === 135) {
      if (poff + 2 > length) break;
      const next = bytes[poff];
      const hdrLen = (bytes[poff + 1] + 1) * 8;
      if (poff + hdrLen > length) break;
      poff += hdrLen;
      nh = next;
    } else if (nh === 44) {
      if (poff + 8 > length) break;
      const next = bytes[poff];
      poff += 8;
      nh = next;
    } else if (nh === 51) {
      if (poff + 2 > length) break;
      const next = bytes[poff];
      const hdrLen = (bytes[poff + 1] + 2) * 4;
      if (poff + hdrLen > length) break;
      poff += hdrLen;
      nh = next;
    } else break;
    hops += 1;
  }
  return { nextHeader: nh, offset: poff };
}

function parseIPv6(bytes, off, length, linkMeta = {}) {
  if (off + 40 > length) return null;
  if ((bytes[off] >> 4) !== 6) return null;
  const src = formatIPv6(bytes, off + 8);
  const dst = formatIPv6(bytes, off + 24);
  const payloadLength = u16be(bytes, off + 4);
  const frameEnd = payloadLength ? Math.min(length, off + 40 + payloadLength) : length;
  const skipped = skipIPv6Extensions(bytes, bytes[off + 6], off + 40, frameEnd);
  const protocolNumber = skipped.nextHeader;
  const protocol = protocolNameIPv6(protocolNumber);
  const poff = skipped.offset;
  let sport = null, dport = null, detail = '', dns = null, service = '', tcpFlags = '';

  if ((protocolNumber === 6 || protocolNumber === 17 || protocolNumber === 132) && poff + 4 <= frameEnd) {
    sport = u16be(bytes, poff);
    dport = u16be(bytes, poff + 2);
    detail = sport + ' -> ' + dport;
    if (protocolNumber === 6 && poff + 20 <= frameEnd) {
      const tcpHeaderLen = ((bytes[poff + 12] >> 4) & 0x0f) * 4;
      tcpFlags = tcpFlagsString(bytes[poff + 13]);
      detail += tcpFlags ? ' ' + tcpFlags : '';
      const payloadOff = poff + tcpHeaderLen;
      const payloadLen = Math.max(0, frameEnd - payloadOff);
      if ((sport === 53 || dport === 53) && payloadLen > 2) {
        const dnsLen = Math.min(payloadLen - 2, u16be(bytes, payloadOff));
        dns = parseDnsMessage(bytes, payloadOff + 2, dnsLen, 'DNS');
      }
    } else if (protocolNumber === 17 && poff + 8 <= frameEnd) {
      const udpLen = u16be(bytes, poff + 4);
      const payloadOff = poff + 8;
      const payloadLen = Math.max(0, Math.min(frameEnd, poff + (udpLen || (frameEnd - poff))) - payloadOff);
      if (DNS_PORTS.has(sport) || DNS_PORTS.has(dport)) {
        const flavor = (sport === 5353 || dport === 5353) ? 'MDNS' : ((sport === 5355 || dport === 5355) ? 'LLMNR' : 'DNS');
        dns = parseDnsMessage(bytes, payloadOff, payloadLen, flavor);
      }
    }
    service = dns ? ((sport === 5353 || dport === 5353) ? 'MDNS' : ((sport === 5355 || dport === 5355) ? 'LLMNR' : 'DNS')) : serviceForPort(protocol, sport, dport);
    if (dns && dns.label) detail = dns.label;
  } else if (protocolNumber === 58 && poff + 2 <= frameEnd) {
    detail = 'type ' + bytes[poff] + ' code ' + bytes[poff + 1];
  }

  return basePacket(src, dst, protocol, linkMeta.origLen || (frameEnd - off), {
    ...linkMeta, sport, dport, detail, dns, service, tcpFlags
  });
}

function parseARP(bytes, off, length, linkMeta = {}) {
  if (off + 28 > length) return null;
  const htype = u16be(bytes, off);
  const ptype = u16be(bytes, off + 2);
  const hlen = bytes[off + 4];
  const plen = bytes[off + 5];
  const oper = u16be(bytes, off + 6);
  if (htype !== 1 || ptype !== 0x0800 || hlen !== 6 || plen !== 4) {
    return basePacket(linkMeta.srcMac || 'ARP', linkMeta.dstMac || 'ARP', 'ARP', linkMeta.origLen || length, { ...linkMeta, detail: 'operation ' + oper });
  }
  const sha = formatMac(bytes, off + 8);
  const spa = formatIPv4(bytes, off + 14);
  const tha = formatMac(bytes, off + 18);
  const tpa = formatIPv4(bytes, off + 24);
  const detail = (oper === 1 ? 'who-has ' : (oper === 2 ? 'is-at ' : 'op ' + oper + ' ')) + tpa;
  return basePacket(spa || sha, tpa || tha, 'ARP', linkMeta.origLen || length, { ...linkMeta, srcMac: sha || linkMeta.srcMac, dstMac: tha || linkMeta.dstMac, detail });
}

function parsePacketByEthType(bytes, ethType, payloadOff, length, linkMeta) {
  if (ethType === 0x0800) return parseIPv4(bytes, payloadOff, length, { ...linkMeta, ethType: '0x0800' });
  if (ethType === 0x86dd) return parseIPv6(bytes, payloadOff, length, { ...linkMeta, ethType: '0x86dd' });
  if (ethType === 0x0806) return parseARP(bytes, payloadOff, length, { ...linkMeta, ethType: '0x0806' });
  return basePacket(linkMeta.srcMac || 'link-src', linkMeta.dstMac || 'link-dst', 'EtherType 0x' + ethType.toString(16).padStart(4, '0'), linkMeta.origLen || length, { ...linkMeta, ethType: '0x' + ethType.toString(16).padStart(4, '0'), detail: 'unsupported EtherType' });
}

function parseEthernet(bytes, capLen, origLen) {
  if (bytes.length < 14) return null;
  const dstMac = formatMac(bytes, 0);
  const srcMac = formatMac(bytes, 6);
  let ethType = u16be(bytes, 12);
  let off = 14;
  const vlans = [];
  while ((ethType === 0x8100 || ethType === 0x88a8 || ethType === 0x9100) && off + 4 <= bytes.length) {
    vlans.push(u16be(bytes, off));
    ethType = u16be(bytes, off + 2);
    off += 4;
  }
  return parsePacketByEthType(bytes, ethType, off, bytes.length, { srcMac, dstMac, vlan: vlans.length ? vlans : null, caplen: capLen, origLen });
}

function parseLinuxSll(bytes, capLen, origLen) {
  if (bytes.length < 16) return null;
  const addrLen = u16be(bytes, 4);
  const addr = addrLen >= 6 ? formatMac(bytes, 6) : '';
  const ethType = u16be(bytes, 14);
  return parsePacketByEthType(bytes, ethType, 16, bytes.length, { srcMac: addr, dstMac: '', caplen: capLen, origLen });
}

function parseLinuxSll2(bytes, capLen, origLen) {
  if (bytes.length < 20) return null;
  const ethType = u16be(bytes, 0);
  const addrLen = bytes[11];
  const addr = addrLen >= 6 ? formatMac(bytes, 12) : '';
  return parsePacketByEthType(bytes, ethType, 20, bytes.length, { srcMac: addr, dstMac: '', caplen: capLen, origLen });
}

function parsePacketBytes(bytes, linkType, capLen, origLen) {
  switch (linkType) {
    case LINKTYPE_ETHERNET: return parseEthernet(bytes, capLen, origLen);
    case LINKTYPE_RAW: {
      const v = bytes[0] >> 4;
      if (v === 4) return parseIPv4(bytes, 0, bytes.length, { caplen: capLen, origLen });
      if (v === 6) return parseIPv6(bytes, 0, bytes.length, { caplen: capLen, origLen });
      return null;
    }
    case LINKTYPE_LINUX_SLL: return parseLinuxSll(bytes, capLen, origLen);
    case LINKTYPE_IPV4: return parseIPv4(bytes, 0, bytes.length, { caplen: capLen, origLen });
    case LINKTYPE_IPV6: return parseIPv6(bytes, 0, bytes.length, { caplen: capLen, origLen });
    case LINKTYPE_LINUX_SLL2: return parseLinuxSll2(bytes, capLen, origLen);
    default: return null;
  }
}

function classifyHost(host) {
  if (!host) return 'remote';
  if (host === '255.255.255.255' || host.toLowerCase() === 'ff:ff:ff:ff:ff:ff') return 'broadcast';
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(host)) {
    const first = parseInt(host.slice(0, 2), 16);
    if ((first & 1) === 1) return 'multicast';
    return 'mac';
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const p = host.split('.').map(Number);
    if (p[0] >= 224 && p[0] <= 239) return 'multicast';
    if (p[0] === 10 || p[0] === 127 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254)) return 'local';
    return 'remote';
  }
  const h = host.toLowerCase();
  if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return 'local';
  if (h.startsWith('ff')) return 'multicast';
  return 'remote';
}

function parseNullSeparatedNames(bytes, off, len) {
  const names = [];
  const end = off + len;
  let start = off;
  for (let i = off; i <= end; i++) {
    if (i === end || bytes[i] === 0) {
      const s = cleanDnsName(safeDecode(bytes, start, i - start));
      if (s) names.push(s);
      start = i + 1;
    }
  }
  return names;
}

function parseNameResolutionBlock(view, bodyStart, bodyEnd, little, allBytes) {
  const records = [];
  let off = bodyStart;
  while (off + 4 <= bodyEnd) {
    const type = view.getUint16(off, little);
    const len = view.getUint16(off + 2, little);
    off += 4;
    if (type === 0) break;
    if (off + len > bodyEnd) break;
    if (type === 1 && len >= 5) {
      const ip = formatIPv4(allBytes, off);
      const names = parseNullSeparatedNames(allBytes, off + 4, len - 4);
      for (const name of names) records.push({ address: ip, name, type: 'NRB', source: 'pcapng-nrb' });
    } else if (type === 2 && len >= 17) {
      const ip = formatIPv6(allBytes, off);
      const names = parseNullSeparatedNames(allBytes, off + 16, len - 16);
      for (const name of names) records.push({ address: ip, name, type: 'NRB', source: 'pcapng-nrb' });
    }
    off += align4(len);
  }
  return records;
}

function reversePtrNameToIP(name) {
  const n = cleanDnsName(name).toLowerCase();
  if (n.endsWith('.in-addr.arpa')) {
    const labels = n.slice(0, -13).split('.').filter(Boolean);
    if (labels.length === 4 && labels.every(x => /^\d+$/.test(x) && Number(x) >= 0 && Number(x) <= 255)) {
      return labels.reverse().join('.');
    }
  }
  if (n.endsWith('.ip6.arpa')) {
    const labels = n.slice(0, -9).split('.').filter(Boolean);
    if (labels.length === 32 && labels.every(x => /^[0-9a-f]$/.test(x))) {
      const hex = labels.reverse().join('');
      const bytes = new Uint8Array(16);
      for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      return formatIPv6(bytes, 0);
    }
  }
  return '';
}

function normalizeNameForResolver(name) {
  const cleaned = cleanDnsName(name);
  if (!cleaned) return '';
  const lower = cleaned.toLowerCase();
  if (lower === 'localhost') return cleaned;
  if (lower.endsWith('.in-addr.arpa') || lower.endsWith('.ip6.arpa')) return '';
  if (lower === '.') return '';
  return cleaned;
}

function addResolution(resolver, address, name, type, ts, source) {
  address = String(address || '').trim();
  name = normalizeNameForResolver(name);
  if (!address || !name) return;
  if (!resolver.ipNames[address]) resolver.ipNames[address] = { address, names: {}, firstSeen: ts, lastSeen: ts };
  if (!resolver.ipNames[address].names[name]) resolver.ipNames[address].names[name] = { name, count: 0, firstSeen: ts, lastSeen: ts, types: {}, sources: {} };
  const n = resolver.ipNames[address].names[name];
  n.count += 1;
  n.firstSeen = Math.min(n.firstSeen, ts);
  n.lastSeen = Math.max(n.lastSeen, ts);
  bump(n.types, type || 'DNS');
  bump(n.sources, source || 'dns');

  const lname = name.toLowerCase();
  if (!resolver.nameIps[lname]) resolver.nameIps[lname] = { name, ips: {}, firstSeen: ts, lastSeen: ts };
  if (!resolver.nameIps[lname].ips[address]) resolver.nameIps[lname].ips[address] = { address, count: 0, firstSeen: ts, lastSeen: ts, types: {}, sources: {} };
  const ip = resolver.nameIps[lname].ips[address];
  ip.count += 1;
  ip.firstSeen = Math.min(ip.firstSeen, ts);
  ip.lastSeen = Math.max(ip.lastSeen, ts);
  bump(ip.types, type || 'DNS');
  bump(ip.sources, source || 'dns');
}

function chooseBestName(entry) {
  if (!entry || !entry.names) return '';
  const candidates = Object.values(entry.names).filter(n => normalizeNameForResolver(n.name));
  if (!candidates.length) return '';
  candidates.sort((a, b) => {
    const alocal = a.name.toLowerCase().endsWith('.local') ? 1 : 0;
    const blocal = b.name.toLowerCase().endsWith('.local') ? 1 : 0;
    return b.count - a.count || b.lastSeen - a.lastSeen || blocal - alocal || a.name.length - b.name.length || a.name.localeCompare(b.name);
  });
  return candidates[0].name;
}

function buildDnsResolver(packets, nrbRecords) {
  const resolver = { ipNames: {}, nameIps: {}, hostLabels: {}, resolutions: [], dnsPacketCount: 0, queryCounts: {}, responseCounts: {} };
  for (const rec of nrbRecords || []) addResolution(resolver, rec.address, rec.name, rec.type || 'NRB', 0, rec.source || 'pcapng-nrb');

  for (const p of packets) {
    if (!p.dns) continue;
    resolver.dnsPacketCount += 1;
    const ts = Number.isFinite(p.ts) ? p.ts : 0;
    for (const q of p.dns.questions || []) {
      if (q.name) bump(resolver.queryCounts, q.name);
    }
    const records = (p.dns.answers || []).concat(p.dns.authorities || [], p.dns.additionals || []);
    const addressRecords = [];
    const cnameRecords = [];
    for (const rec of records) {
      if ((rec.type === 1 || rec.type === 28) && rec.address && rec.name) {
        addResolution(resolver, rec.address, rec.name, rec.typeName, ts, p.service || 'dns');
        addressRecords.push(rec);
        bump(resolver.responseCounts, rec.name);
      } else if (rec.type === 5 && rec.name && rec.data) {
        cnameRecords.push(rec);
      } else if (rec.type === 12 && rec.name && rec.data) {
        const ip = reversePtrNameToIP(rec.name);
        if (ip) addResolution(resolver, ip, rec.data, 'PTR', ts, p.service || 'dns');
      }
    }
    for (const c of cnameRecords) {
      for (const a of addressRecords) {
        if (cleanDnsName(a.name).toLowerCase() === cleanDnsName(c.data).toLowerCase()) {
          addResolution(resolver, a.address, c.name, 'CNAME+' + a.typeName, ts, p.service || 'dns');
        }
      }
    }
  }

  for (const [ip, entry] of Object.entries(resolver.ipNames)) {
    const best = chooseBestName(entry);
    if (best) resolver.hostLabels[ip] = best;
    const names = Object.values(entry.names).sort((a, b) => b.count - a.count || b.lastSeen - a.lastSeen || a.name.localeCompare(b.name));
    for (const n of names) {
      resolver.resolutions.push({ address: ip, name: n.name, count: n.count, firstSeen: n.firstSeen, lastSeen: n.lastSeen, types: sortedEntriesFromMapObj(n.types), sources: sortedEntriesFromMapObj(n.sources) });
    }
  }
  resolver.resolutions.sort((a, b) => b.count - a.count || b.lastSeen - a.lastSeen || a.address.localeCompare(b.address));
  resolver.queryCounts = sortedEntriesFromMapObj(resolver.queryCounts).slice(0, 5000);
  resolver.responseCounts = sortedEntriesFromMapObj(resolver.responseCounts).slice(0, 5000);
  return resolver;
}

function packetSearchString(p, resolver) {
  const parts = [p.src, p.dst, p.srcLabel, p.dstLabel, p.protocol, p.service, p.detail, p.sport, p.dport, p.srcMac, p.dstMac, p.ethType];
  const srcEntry = resolver.ipNames[p.src];
  const dstEntry = resolver.ipNames[p.dst];
  if (srcEntry) parts.push(...Object.keys(srcEntry.names));
  if (dstEntry) parts.push(...Object.keys(dstEntry.names));
  if (p.dns) {
    parts.push(p.dns.label, p.dns.qr);
    for (const q of p.dns.questions || []) parts.push(q.name, q.typeName);
    for (const rec of (p.dns.answers || []).concat(p.dns.authorities || [], p.dns.additionals || [])) parts.push(rec.name, rec.typeName, rec.data, rec.address);
  }
  return parts.filter(v => v !== null && v !== undefined && v !== '').join(' ').toLowerCase();
}

function enrichPacketsAndSummarize(packets, interfaces, meta) {
  packets.sort((a, b) => a.ts - b.ts || a.index - b.index);
  const firstTs = packets.length ? packets[0].ts : null;
  const lastTs = packets.length ? packets[packets.length - 1].ts : null;
  for (let i = 0; i < packets.length; i++) {
    packets[i].index = i;
    packets[i].rel = firstTs == null ? 0 : packets[i].ts - firstTs;
  }

  const resolver = buildDnsResolver(packets, meta.nrbRecords || []);
  for (const p of packets) {
    p.srcLabel = resolver.hostLabels[p.src] || p.src;
    p.dstLabel = resolver.hostLabels[p.dst] || p.dst;
    const srcEntry = resolver.ipNames[p.src];
    const dstEntry = resolver.ipNames[p.dst];
    p.srcNames = srcEntry ? Object.keys(srcEntry.names).slice(0, 8) : [];
    p.dstNames = dstEntry ? Object.keys(dstEntry.names).slice(0, 8) : [];
    p.search = packetSearchString(p, resolver);
  }

  const hostStats = {};
  const protocolCounts = {};
  const serviceCounts = {};
  const pairCounts = {};
  let bytesDecoded = 0;
  for (const p of packets) {
    bytesDecoded += p.bytes || 0;
    bump(protocolCounts, p.protocol);
    bump(serviceCounts, p.service || p.protocol);
    bump(pairCounts, p.src + '\u0000' + p.dst);
    if (!hostStats[p.src]) hostStats[p.src] = { host: p.src, label: p.srcLabel, names: p.srcNames || [], className: classifyHost(p.src), sentPackets: 0, recvPackets: 0, sentBytes: 0, recvBytes: 0, totalPackets: 0, totalBytes: 0 };
    if (!hostStats[p.dst]) hostStats[p.dst] = { host: p.dst, label: p.dstLabel, names: p.dstNames || [], className: classifyHost(p.dst), sentPackets: 0, recvPackets: 0, sentBytes: 0, recvBytes: 0, totalPackets: 0, totalBytes: 0 };
    hostStats[p.src].label = p.srcLabel;
    hostStats[p.dst].label = p.dstLabel;
    hostStats[p.src].sentPackets += 1;
    hostStats[p.src].sentBytes += p.bytes || 0;
    hostStats[p.src].totalPackets += 1;
    hostStats[p.src].totalBytes += p.bytes || 0;
    hostStats[p.dst].recvPackets += 1;
    hostStats[p.dst].recvBytes += p.bytes || 0;
    hostStats[p.dst].totalPackets += 1;
    hostStats[p.dst].totalBytes += p.bytes || 0;
  }

  const topPairs = Object.entries(pairCounts).map(([key, count]) => {
    const parts = key.split('\u0000');
    return { src: parts[0], dst: parts[1], srcLabel: resolver.hostLabels[parts[0]] || parts[0], dstLabel: resolver.hostLabels[parts[1]] || parts[1], count };
  }).sort((a, b) => b.count - a.count).slice(0, 100);

  return {
    packets,
    interfaces,
    dns: resolver,
    summary: {
      parser: 'pcapng-traffic-movie-v2-core',
      fileType: meta.fileType || 'pcapng',
      fileBytes: meta.fileBytes,
      packetsDecoded: packets.length,
      bytesDecoded,
      duration: firstTs == null || lastTs == null ? 0 : lastTs - firstTs,
      firstTs,
      lastTs,
      hostCount: Object.keys(hostStats).length,
      protocolCounts: sortedEntriesFromMapObj(protocolCounts),
      serviceCounts: sortedEntriesFromMapObj(serviceCounts),
      hostStats: Object.values(hostStats).sort((a, b) => b.totalPackets - a.totalPackets || a.host.localeCompare(b.host)),
      topPairs,
      blockCounts: meta.blockCounts || {},
      linkTypes: meta.linkTypes || {},
      skippedByReason: meta.skippedByReason || {},
      malformedBlocks: meta.malformedBlocks || 0,
      warnings: meta.warnings || [],
      dnsPacketCount: resolver.dnsPacketCount,
      dnsResolutionCount: resolver.resolutions.length,
      nrbRecordCount: (meta.nrbRecords || []).length
    }
  };
}

function parsePcapng(arrayBuffer, options = {}) {
  const view = new DataView(arrayBuffer);
  const allBytes = new Uint8Array(arrayBuffer);
  const packets = [];
  const interfaces = [];
  const warnings = [];
  const blockCounts = {};
  const linkTypes = {};
  const skippedByReason = {};
  const nrbRecords = [];
  const maxPackets = Number.isFinite(options.maxPackets) ? options.maxPackets : Infinity;
  const progressEveryBytes = options.progressEveryBytes || Math.max(1024 * 1024, Math.floor(arrayBuffer.byteLength / 50));
  let nextProgressAt = progressEveryBytes;
  let offset = 0;
  let section = null;
  let sectionIndex = -1;
  let malformedBlocks = 0;

  function reportProgress(force = false) {
    if (typeof options.onProgress === 'function' && (force || offset >= nextProgressAt)) {
      options.onProgress({ offset, size: arrayBuffer.byteLength, packets: packets.length, phase: 'pcapng' });
      while (nextProgressAt <= offset) nextProgressAt += progressEveryBytes;
    }
  }

  while (offset + 12 <= arrayBuffer.byteLength) {
    reportProgress(false);
    const typeLE = view.getUint32(offset, true);
    const typeBE = view.getUint32(offset, false);
    if (typeLE === BLOCK_SHB || typeBE === BLOCK_SHB) {
      let little;
      if (view.getUint32(offset + 8, true) === BYTE_ORDER_MAGIC) little = true;
      else if (view.getUint32(offset + 8, false) === BYTE_ORDER_MAGIC) little = false;
      else { warnings.push('Section Header Block at ' + offset + ' has an unknown byte-order magic.'); break; }
      const blockLen = view.getUint32(offset + 4, little);
      if (blockLen < 28 || offset + blockLen > arrayBuffer.byteLength) { warnings.push('Section Header Block at ' + offset + ' has invalid length ' + blockLen + '.'); malformedBlocks += 1; break; }
      sectionIndex += 1;
      section = { little, interfaces: [], sectionIndex };
      bump(blockCounts, 'SHB');
      offset += blockLen;
      continue;
    }
    if (!section) { warnings.push('Found block before first Section Header Block at offset ' + offset + '.'); break; }
    const little = section.little;
    const blockType = view.getUint32(offset, little);
    const blockLen = view.getUint32(offset + 4, little);
    if (blockLen < 12 || offset + blockLen > arrayBuffer.byteLength) { warnings.push('Block ' + blockName(blockType) + ' at ' + offset + ' has invalid length ' + blockLen + '.'); malformedBlocks += 1; break; }
    const bodyStart = offset + 8;
    const bodyEnd = offset + blockLen - 4;
    bump(blockCounts, blockName(blockType));

    if (blockType === BLOCK_IDB) {
      if (bodyStart + 8 <= bodyEnd) {
        const linkType = view.getUint16(bodyStart, little);
        const snapLen = view.getUint32(bodyStart + 4, little);
        const ifaceOptions = parseInterfaceOptions(view, bodyStart + 8, bodyEnd, little);
        const iface = { id: section.interfaces.length, globalId: interfaces.length, sectionIndex, linkType, snapLen, tsresol: ifaceOptions.tsresol, tsoffset: ifaceOptions.tsoffset, name: ifaceOptions.name, description: ifaceOptions.description, comment: ifaceOptions.comment };
        section.interfaces.push(iface);
        interfaces.push(iface);
        bump(linkTypes, String(linkType));
      }
    } else if (blockType === BLOCK_NRB) {
      const recs = parseNameResolutionBlock(view, bodyStart, bodyEnd, little, allBytes);
      for (const rec of recs) nrbRecords.push(rec);
    } else if (blockType === BLOCK_EPB) {
      if (bodyStart + 20 <= bodyEnd) {
        const interfaceId = view.getUint32(bodyStart, little);
        const tsHigh = view.getUint32(bodyStart + 4, little);
        const tsLow = view.getUint32(bodyStart + 8, little);
        const capLen = view.getUint32(bodyStart + 12, little);
        const origLen = view.getUint32(bodyStart + 16, little);
        const packetStart = bodyStart + 20;
        const packetEnd = packetStart + capLen;
        const iface = section.interfaces[interfaceId];
        if (!iface) bump(skippedByReason, 'missing_interface');
        else if (capLen > origLen && origLen !== 0) bump(skippedByReason, 'caplen_gt_origlen');
        else if (packetEnd > bodyEnd) bump(skippedByReason, 'truncated_epb');
        else if (packets.length < maxPackets) {
          const packetBytes = allBytes.subarray(packetStart, packetEnd);
          const decoded = parsePacketBytes(packetBytes, iface.linkType, capLen, origLen || capLen);
          const ts = (tsHigh * TWO_32 + tsLow) * iface.tsresol + iface.tsoffset;
          if (decoded && decoded.src && decoded.dst) {
            decoded.ts = ts;
            decoded.iface = iface.globalId;
            decoded.linkType = iface.linkType;
            decoded.index = packets.length;
            packets.push(decoded);
          } else bump(skippedByReason, 'unsupported_or_malformed_linktype_' + iface.linkType);
        }
      }
    } else if (blockType === BLOCK_SPB) {
      bump(skippedByReason, 'simple_packet_no_timestamp');
    }
    offset += blockLen;
  }
  reportProgress(true);
  return enrichPacketsAndSummarize(packets, interfaces, { fileType: 'pcapng', fileBytes: arrayBuffer.byteLength, blockCounts, linkTypes, skippedByReason, malformedBlocks, warnings, nrbRecords });
}

function detectPcap(arrayBuffer) {
  if (arrayBuffer.byteLength < 24) return null;
  const view = new DataView(arrayBuffer);
  const be = view.getUint32(0, false);
  const le = view.getUint32(0, true);
  if (be === 0xa1b2c3d4) return { little: false, tsresol: 1e-6 };
  if (le === 0xa1b2c3d4) return { little: true, tsresol: 1e-6 };
  if (be === 0xa1b23c4d) return { little: false, tsresol: 1e-9 };
  if (le === 0xa1b23c4d) return { little: true, tsresol: 1e-9 };
  return null;
}

function parsePcap(arrayBuffer, options = {}) {
  const det = detectPcap(arrayBuffer);
  if (!det) throw new Error('Not a classic PCAP file.');
  const view = new DataView(arrayBuffer);
  const allBytes = new Uint8Array(arrayBuffer);
  const little = det.little;
  const snapLen = view.getUint32(16, little);
  const linkType = view.getUint32(20, little);
  const packets = [];
  const warnings = [];
  const skippedByReason = {};
  const linkTypes = {}; bump(linkTypes, String(linkType));
  const progressEveryBytes = options.progressEveryBytes || Math.max(1024 * 1024, Math.floor(arrayBuffer.byteLength / 50));
  let nextProgressAt = progressEveryBytes;
  let off = 24;
  function reportProgress(force = false) {
    if (typeof options.onProgress === 'function' && (force || off >= nextProgressAt)) {
      options.onProgress({ offset: off, size: arrayBuffer.byteLength, packets: packets.length, phase: 'pcap' });
      while (nextProgressAt <= off) nextProgressAt += progressEveryBytes;
    }
  }
  while (off + 16 <= arrayBuffer.byteLength) {
    reportProgress(false);
    const tsSec = view.getUint32(off, little);
    const tsFrac = view.getUint32(off + 4, little);
    const capLen = view.getUint32(off + 8, little);
    const origLen = view.getUint32(off + 12, little);
    off += 16;
    if (off + capLen > arrayBuffer.byteLength) { warnings.push('Truncated packet record at offset ' + (off - 16) + '.'); break; }
    const packetBytes = allBytes.subarray(off, off + capLen);
    const decoded = parsePacketBytes(packetBytes, linkType, capLen, origLen || capLen);
    if (decoded && decoded.src && decoded.dst) {
      decoded.ts = tsSec + tsFrac * det.tsresol;
      decoded.iface = 0;
      decoded.linkType = linkType;
      decoded.index = packets.length;
      packets.push(decoded);
    } else bump(skippedByReason, 'unsupported_or_malformed_linktype_' + linkType);
    off += capLen;
  }
  reportProgress(true);
  const interfaces = [{ id: 0, globalId: 0, sectionIndex: 0, linkType, snapLen, tsresol: det.tsresol, tsoffset: 0, name: 'pcap0', description: 'Classic PCAP interface', comment: '' }];
  return enrichPacketsAndSummarize(packets, interfaces, { fileType: 'pcap', fileBytes: arrayBuffer.byteLength, blockCounts: { PCAP_RECORD: packets.length }, linkTypes, skippedByReason, malformedBlocks: 0, warnings, nrbRecords: [] });
}

function parseCapture(arrayBuffer, options = {}) {
  const view = new DataView(arrayBuffer);
  if (arrayBuffer.byteLength >= 12 && (view.getUint32(0, true) === BLOCK_SHB || view.getUint32(0, false) === BLOCK_SHB)) return parsePcapng(arrayBuffer, options);
  if (detectPcap(arrayBuffer)) return parsePcap(arrayBuffer, options);
  throw new Error('Unsupported capture format. Expected PCAPNG or classic PCAP.');
}

function summarizeForReport(parsed) {
  const s = parsed.summary || {};
  return {
    fileBytes: s.fileBytes,
    fileType: s.fileType,
    packetsDecoded: s.packetsDecoded,
    bytesDecoded: s.bytesDecoded,
    durationSeconds: s.duration,
    firstTimestamp: s.firstTs,
    lastTimestamp: s.lastTs,
    hostCount: s.hostCount,
    dnsPacketCount: s.dnsPacketCount,
    dnsResolutionCount: s.dnsResolutionCount,
    nrbRecordCount: s.nrbRecordCount,
    interfaces: parsed.interfaces,
    blockCounts: s.blockCounts,
    linkTypes: s.linkTypes,
    protocolCounts: s.protocolCounts,
    serviceCounts: (s.serviceCounts || []).slice(0, 20),
    topHosts: (s.hostStats || []).slice(0, 20),
    topDnsResolutions: (parsed.dns && parsed.dns.resolutions ? parsed.dns.resolutions : []).slice(0, 50),
    topDnsQueries: (parsed.dns && parsed.dns.queryCounts ? parsed.dns.queryCounts : []).slice(0, 50),
    skippedByReason: s.skippedByReason,
    warnings: s.warnings
  };
}

if (typeof self !== 'undefined' && typeof self.postMessage === 'function') {
  self.onmessage = (event) => {
    const msg = event.data || {};
    if (msg.type !== 'parse') return;
    const started = Date.now();
    try {
      const parsed = parseCapture(msg.buffer, {
        onProgress: progress => self.postMessage({ type: 'progress', progress })
      });
      parsed.summary.parseMillis = Date.now() - started;
      self.postMessage({ type: 'done', name: msg.name || 'capture.pcapng', parsed });
    } catch (error) {
      self.postMessage({ type: 'error', message: error && error.stack ? error.stack : String(error) });
    }
  };
}

if (typeof module !== 'undefined') {
  module.exports = { parseCapture, parsePcapng, parsePcap, parseDnsMessage, summarizeForReport, classifyHost };
}
