const os = require('os');
const { spawn, exec } = require('child_process');

// ── State ─────────────────────────────────────────────────────────────────────
let tshark = null;
let capturing = false;
let currentIface = '';
let statsTimer = null;
let packetId = 0;
let stats = makeStats();

// ── Capture config (runtime adjustable) ───────────────────────────────────────
let captureConfig = {
  bufferSize:   5000,    // packets/sec limit (1000–10000)
  promiscuous:  false,   // true = -p flag removed (promiscuous on), false = -p (off)
};

function makeStats() {
  return {
    total: 0,
    encrypted: 0,
    unencrypted: 0,
    protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, FTP: 0, TELNET: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
    startTime: Date.now()
  };
}

// ── Port tables ───────────────────────────────────────────────────────────────
const PORT_PROTO = {
  80: 'HTTP', 8080: 'HTTP',
  443: 'HTTPS', 8443: 'HTTPS', 465: 'HTTPS', 993: 'HTTPS', 995: 'HTTPS', 587: 'HTTPS',
  22: 'SSH',
  53: 'DNS',
  21: 'FTP', 20: 'FTP',
  23: 'TELNET',
};

const ENCRYPTED_PROTOS = new Set(['HTTPS', 'SSH']);

const TLS_VERSION_MAP = {
  '0x0304': 'TLS 1.3',
  '0x0303': 'TLS 1.2',
  '0x0302': 'TLS 1.1',
  '0x0301': 'TLS 1.0',
  '0x0300': 'SSL 3.0',
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function toPort(value) {
  const p = parseInt(value, 10);
  return Number.isNaN(p) ? null : p;
}

function getLocalIP() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return null;
}

// ── Protocol / encryption detection ──────────────────────────────────────────
function parseTlsVersion(raw) {
  if (!raw || raw.trim() === '') return null;
  const trimmed = raw.trim();
  if (TLS_VERSION_MAP[trimmed]) return TLS_VERSION_MAP[trimmed];
  const upper = trimmed.toUpperCase();
  if (upper.includes('1.3')) return 'TLS 1.3';
  if (upper.includes('1.2')) return 'TLS 1.2';
  if (upper.includes('1.1')) return 'TLS 1.1';
  if (upper.includes('1.0')) return 'TLS 1.0';
  if (upper.includes('SSL')) return 'SSL 3.0';
  return null;
}

function normalizeProtocol(tsharkProto, srcPort, dstPort, tlsVer) {
  const src = toPort(srcPort);
  const dst = toPort(dstPort);
  const p = tsharkProto ? tsharkProto.toUpperCase().trim() : '';

  if (tlsVer) return 'HTTPS';
  if (p === 'TLS' || p === 'SSL' || p.startsWith('TLS'))   return 'HTTPS';
  if (p === 'HTTP' || p === 'HTTP2' || p === 'HTTP/2')      return 'HTTP';
  if (p === 'DNS')                                           return 'DNS';
  if (p === 'SSH')                                           return 'SSH';
  if (p === 'FTP' || p === 'FTP-DATA')                      return 'FTP';
  if (p === 'TELNET')                                        return 'TELNET';
  if (p === 'ICMP' || p === 'ICMPv6')                       return 'ICMP';
  if (p === 'UDP')                                           return 'UDP';

  const fromPort = PORT_PROTO[dst] || PORT_PROTO[src];
  if (fromPort) return fromPort;

  if (p === 'TCP' || src !== null) return 'TCP';
  return 'OTHER';
}

function detectEncryption(protocol, tlsVer) {
  if (tlsVer) return true;
  return ENCRYPTED_PROTOS.has(protocol);
}

function resolveTlsLabel(protocol, tlsVer, srcPort, dstPort) {
  if (tlsVer) return tlsVer;
  const src = toPort(srcPort);
  const dst = toPort(dstPort);
  if (protocol === 'SSH' || src === 22 || dst === 22) return 'SSH-2.0';
  if (protocol === 'HTTPS') return 'TLS (data)';
  return '-';
}

// ── Buffer rate limiter ───────────────────────────────────────────────────────
// Simple token-bucket: allow at most `captureConfig.bufferSize` packets/sec
let tokenBucket = 0;
let lastTokenRefill = Date.now();

function acquireToken() {
  const now = Date.now();
  const elapsed = (now - lastTokenRefill) / 1000;
  tokenBucket += elapsed * captureConfig.bufferSize;
  if (tokenBucket > captureConfig.bufferSize) tokenBucket = captureConfig.bufferSize;
  lastTokenRefill = now;

  if (tokenBucket >= 1) {
    tokenBucket -= 1;
    return true;
  }
  return false;
}

// ── Parse one tshark output line ──────────────────────────────────────────────
function parseLine(line) {
  const parts = line.split('\t');
  if (parts.length < 9) return null;

  const [src, dst, tcpSrc, tcpDst, udpSrc, udpDst, tsharkProto, tlsRaw, lenRaw] = parts;
  if (!src || !dst || src.trim() === '' || dst.trim() === '') return null;

  const srcPort  = tcpSrc.trim() || udpSrc.trim() || '-';
  const dstPort  = tcpDst.trim() || udpDst.trim() || '-';
  const tlsVer   = parseTlsVersion(tlsRaw);
  const protocol = normalizeProtocol(tsharkProto, srcPort, dstPort, tlsVer);
  const encrypted= detectEncryption(protocol, tlsVer);
  const tlsLabel = resolveTlsLabel(protocol, tlsVer, srcPort, dstPort);
  const size     = parseInt(lenRaw, 10) || 0;

  return {
    id:         ++packetId,
    timestamp:  new Date().toISOString(),
    time:       new Date().toLocaleTimeString('th-TH'),
    srcIP:      src.trim(),
    dstIP:      dst.trim(),
    srcPort,
    dstPort,
    protocol,
    size,
    tlsVersion: tlsLabel,
    encrypted,
  };
}

// ── Stats / emit helpers ──────────────────────────────────────────────────────
function emitStats(io) {
  if (!io) return;
  const elapsed = (Date.now() - stats.startTime) / 1000 || 1;
  io.emit('stats', {
    total:        stats.total,
    encrypted:    stats.encrypted,
    unencrypted:  stats.unencrypted,
    encryptedPct: stats.total > 0 ? Math.round((stats.encrypted / stats.total) * 100) : 0,
    protocols:    { ...stats.protocols },
    pps:          Math.round(stats.total / Math.max(1, elapsed)),
    uptime:       Math.round(elapsed),
    config:       { bufferSize: captureConfig.bufferSize, promiscuous: captureConfig.promiscuous },
  });
}

function emitPacket(io, pkt) {
  if (!pkt || !io) return;

  // Apply buffer rate limit
  if (!acquireToken()) return;

  stats.total++;
  if (pkt.encrypted) stats.encrypted++;
  else stats.unencrypted++;

  if (stats.protocols[pkt.protocol] !== undefined) stats.protocols[pkt.protocol]++;
  else stats.protocols.OTHER++;

  io.emit('packet', pkt);

  // Security alerts from server side
  const INSECURE = { HTTP: true, FTP: true, TELNET: true };
  if (INSECURE[pkt.protocol]) {
    io.emit('alert', {
      type: pkt.protocol === 'TELNET' ? 'danger' : 'warn',
      message: `[${pkt.protocol}] ${pkt.srcIP}:${pkt.srcPort} → ${pkt.dstIP}:${pkt.dstPort} — ไม่มีการเข้ารหัส`,
    });
  }

  if (stats.total % 50 === 0) emitStats(io);
}

// ── tshark process ────────────────────────────────────────────────────────────
function buildTsharkArgs(iface, filter) {
  let bpf = filter || '';
  const myIP = getLocalIP();

  if (bpf.trim().toLowerCase() === 'ip' && myIP && !captureConfig.promiscuous) {
    bpf = `host ${myIP}`;
    console.log(`[capture] auto BPF filter: ${bpf}`);
  }

  if (!bpf) {
    if (myIP && !captureConfig.promiscuous) {
      bpf = `host ${myIP}`;
      console.log(`[capture] auto BPF filter: ${bpf}`);
    } else if (!myIP) {
      console.warn('[capture] ⚠️  ตรวจ local IP ไม่ได้ — ดักจับทุก packet');
    }
  }

  const args = [
    '-i', iface,
    '-l',
    '-n',
    '-T', 'fields',
    '-E', 'separator=\t',
    '-E', 'occurrence=f',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'tcp.srcport',
    '-e', 'tcp.dstport',
    '-e', 'udp.srcport',
    '-e', 'udp.dstport',
    '-e', '_ws.col.Protocol',
    '-e', 'tls.record.version',
    '-e', 'frame.len',
  ];

  // Promiscuous mode: tshark default is promiscuous ON; use -p to disable it
  // So: normal mode → add -p (no promiscuous), promiscuous → don't add -p
  if (!captureConfig.promiscuous) {
    args.push('-p'); // disable promiscuous = capture only own traffic
  }

  if (bpf) args.push('-f', bpf);

  return args;
}

function startTshark(io, iface, filter) {
  const tsharkPath = 'C:\\Program Files\\Wireshark\\tshark.exe';
  const args = buildTsharkArgs(iface, filter);

  console.log(`[capture] starting tshark | promiscuous=${captureConfig.promiscuous} | buffer=${captureConfig.bufferSize} p/s`);
  console.log(`[capture] args: ${args.join(' ')}`);

  tshark = spawn(tsharkPath, args, { windowsHide: true });

  let leftover = '';

  tshark.stdout.on('data', (data) => {
    const chunk = leftover + data.toString('utf8');
    const lines = chunk.split('\n');
    leftover = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      const pkt = parseLine(line);
      if (pkt) emitPacket(io, pkt);
    }
  });

  tshark.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg.toLowerCase().includes('error') || msg.toLowerCase().includes('failed')) {
      console.error('[tshark error]', msg);
      if (io) io.emit('error', { message: msg });
    }
  });

  tshark.on('exit', (code, signal) => {
    capturing = false;
    console.log(`[tshark] exit code=${code} signal=${signal}`);
    if (io) io.emit('capture:status', { capturing: false });
  });

  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(() => emitStats(io), 2000);

  // reset token bucket on start
  tokenBucket = captureConfig.bufferSize;
  lastTokenRefill = Date.now();

  capturing = true;
  currentIface = iface;
  if (io) {
    io.emit('capture:status', {
      capturing: true,
      interface: iface,
      config: { ...captureConfig },
    });
    emitStats(io);
  }
}

function stopTshark() {
  capturing = false;
  if (tshark) { tshark.kill('SIGTERM'); tshark = null; }
  exec('taskkill /IM tshark.exe /F', () => {});
  if (statsTimer) { clearInterval(statsTimer); statsTimer = null; }
}

// ── Public API ────────────────────────────────────────────────────────────────
module.exports = {
  start(iface = '5', filter = '', io) {
    if (capturing) stopTshark();
    stats    = makeStats();
    packetId = 0;
    startTshark(io, iface, filter);
  },

  stop: stopTshark,

  /**
   * Apply runtime config changes (bufferSize, promiscuous).
   * If capturing, restart tshark so promiscuous flag takes effect.
   */
  applyConfig(newConfig = {}, io) {
    let needRestart = false;

    if (typeof newConfig.bufferSize === 'number') {
      const clamped = Math.max(1000, Math.min(10000, newConfig.bufferSize));
      captureConfig.bufferSize = clamped;
      console.log(`[capture] bufferSize → ${clamped}`);
    }

    if (typeof newConfig.promiscuous === 'boolean') {
      if (captureConfig.promiscuous !== newConfig.promiscuous) {
        captureConfig.promiscuous = newConfig.promiscuous;
        needRestart = true; // tshark needs -p flag change
        console.log(`[capture] promiscuous → ${newConfig.promiscuous}`);
      }
    }

    if (needRestart && capturing) {
      console.log('[capture] restarting tshark to apply promiscuous mode change...');
      const iface  = currentIface;
      stopTshark();
      stats    = makeStats();
      packetId = 0;
      startTshark(io, iface, '');
    }

    if (io) {
      io.emit('capture:config:ack', { ...captureConfig });
    }
  },

  isCapturing:  () => capturing,
  getInterface: () => currentIface,
  getStats:     () => ({ ...stats }),
  getConfig:    () => ({ ...captureConfig }),
};