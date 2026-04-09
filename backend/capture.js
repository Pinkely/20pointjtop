const os = require('os');
const { spawn } = require('child_process');

let tshark = null;
let capturing = false;
let currentIface = '';
let stats = {
  total: 0,
  encrypted: 0,
  unencrypted: 0,
  protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
  startTime: null
};
let statsTimer = null;
let packetId = 0;

const ENCRYPTED_PORTS = new Set([443, 8443, 465, 993, 995, 587]);
const SSH_PORTS = new Set([22]);

function getLocalIP() {
  const interfaces = os.networkInterfaces();

  for (let name in interfaces) {
    for (let iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
}

const myIP = getLocalIP();
console.log('My IP:', myIP);

function toPort(value) {
  const p = parseInt(value, 10);
  return Number.isNaN(p) ? null : p;
}

function isEncryptedPort(srcPort, dstPort) {
  const src = toPort(srcPort);
  const dst = toPort(dstPort);
  return (src && (ENCRYPTED_PORTS.has(src) || SSH_PORTS.has(src))) ||
         (dst && (ENCRYPTED_PORTS.has(dst) || SSH_PORTS.has(dst)));
}

function normalizeProtocol(proto, srcPort, dstPort, tlsVer) {
  const p = proto ? proto.toUpperCase() : '';
  const src = toPort(srcPort);
  const dst = toPort(dstPort);

  // 🔐 TLS จริง (แม่นสุด)
  if (tlsVer && tlsVer !== '') return 'HTTPS';

  // 🔐 HTTPS port
  if (src === 443 || dst === 443) return 'HTTPS';

  // 🔐 SSH
  if (src === 22 || dst === 22) return 'SSH';

  // 🌐 DNS
  if (p.includes('DNS')) return 'DNS';

  // 🌐 HTTP
  if (src === 80 || dst === 80) return 'HTTP';

  // 🧠 protocol จาก tshark
  if (p.includes('HTTP')) return 'HTTP';
  if (p.includes('UDP')) return 'UDP';
  if (p.includes('ICMP')) return 'ICMP';

  // TCP fallback
  if (p.includes('TCP')) return 'TCP';

  return 'OTHER';
}

function isEncrypted(proto, srcPort, dstPort, tlsVer) {
  const src = toPort(srcPort);
  const dst = toPort(dstPort);

  if (tlsVer && tlsVer !== '') return true;
  if (src === 443 || dst === 443) return true;
  if (src === 22 || dst === 22) return true;

  return false;
}

function tlsVersionFromProto(proto, srcPort, dstPort) {
  const p = proto ? proto.toUpperCase() : '';
  if (p.includes('TLS 1.3') || p.includes('TLS1.3')) return 'TLS 1.3';
  if (p.includes('TLS 1.2') || p.includes('TLS1.2')) return 'TLS 1.2';
  if (p.includes('TLS 1.1') || p.includes('TLS1.1')) return 'TLS 1.1';
  if (p.includes('TLS 1.0') || p.includes('TLS1.0')) return 'TLS 1.0';
  if (p.includes('SSL')) return 'SSL 3.0';
  if (p.includes('SSH')) return 'SSH-2.0';
  if (p.includes('HTTPS')) return 'TLS 1.3';
  if (isEncryptedPort(srcPort, dstPort)) {
    return SSH_PORTS.has(toPort(srcPort)) || SSH_PORTS.has(toPort(dstPort)) ? 'SSH-2.0' : 'TLS 1.3';
  }
  return '-';
}

function emitStats(io) {
  if (!io) return;
  const elapsed = stats.startTime ? (Date.now() - stats.startTime) / 1000 : 1;
  io.emit('stats', {
    total: stats.total,
    encrypted: stats.encrypted,
    unencrypted: stats.unencrypted,
    encryptedPct: stats.total > 0 ? Math.round((stats.encrypted / stats.total) * 100) : 0,
    protocols: { ...stats.protocols },
    pps: Math.round(stats.total / Math.max(1, elapsed)),
    uptime: Math.round(elapsed)
  });
}

function resetStats() {
  stats = {
    total: 0,
    encrypted: 0,
    unencrypted: 0,
    protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
    startTime: Date.now()
  };
  packetId = 0;
}

function emitPacket(io, pkt) {
  if (!pkt || !io) return;

  stats.total += 1;
  if (pkt.encrypted) stats.encrypted += 1;
  else stats.unencrypted += 1;

  if (stats.protocols[pkt.protocol] !== undefined) stats.protocols[pkt.protocol] += 1;
  else stats.protocols.OTHER += 1;

  io.emit('packet', pkt);
  if (stats.total % 50 === 0) emitStats(io);
}

function parseLine(line) {
  const [src, dst, tcpSrc, tcpDst, udpSrc, udpDst, proto, tlsVer, len] = line.split('\t');
  if (!src || !dst) return null;

  const srcPort = tcpSrc || udpSrc || '-';
  const dstPort = tcpDst || udpDst || '-';
  const protocol = normalizeProtocol(proto, srcPort, dstPort, tlsVer);
  const encrypted = isEncrypted(proto, srcPort, dstPort, tlsVer);  const tlsVersion = tlsVersionFromProto(proto, srcPort, dstPort);
  const size = parseInt(len, 10) || 0;

  return {
    id: ++packetId,
    timestamp: new Date().toISOString(),
    time: new Date().toLocaleTimeString('th-TH'),
    srcIP: src,
    dstIP: dst,
    srcPort,
    dstPort,
    protocol,
    size,
    tlsVersion: tlsVersion || '-',
    encrypted
  };
}

// 🔹 หา IP เครื่อง
function getLocalIP() {
  const interfaces = os.networkInterfaces();

  for (let name in interfaces) {
    for (let iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return null;
}

function startTshark(io, iface = '5', filter = '') {
  const tsharkPath = 'C:\\Program Files\\Wireshark\\tshark.exe';

  // 🔥 auto filter
  if (!filter) {
    const myIP = getLocalIP();

    if (myIP) {
      console.log('Using IP filter:', myIP);
      filter = `host ${myIP}`;
    } else {
      console.warn('⚠️ Cannot detect local IP');
    }
  }

  const args = [
    '-i', iface,
    '-l',
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'tcp.srcport',
    '-e', 'tcp.dstport',
    '-e', 'udp.srcport',
    '-e', 'udp.dstport',
    '-e', '_ws.col.Protocol',
    '-e', 'tcp.port',
    '-e', 'tls.record.version',
    '-e', 'frame.len'
  ];

  if (filter) {
    args.unshift('-f', filter);
  }

  tshark = spawn(tsharkPath, args, { windowsHide: true });

  let leftover = '';

  tshark.stdout.on('data', (data) => {
    const chunk = leftover + data.toString();
    const lines = chunk.split('\n');
    leftover = lines.pop();

    lines.forEach((line) => {
      if (!line.trim()) return;

      const pkt = parseLine(line);
      if (pkt) emitPacket(io, pkt);
    });
  });

  tshark.stderr.on('data', (err) => {
    console.error('[tshark]', err.toString());
    if (io) io.emit('error', { message: err.toString() });
  });

  tshark.on('exit', (code, signal) => {
    capturing = false;
    if (io) io.emit('capture:status', { capturing: false });
    console.log(`tshark exited code=${code} signal=${signal}`);
  });

  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(() => emitStats(io), 2000);

  capturing = true;
  currentIface = iface;

  if (io) {
    io.emit('capture:status', { capturing: true, interface: iface });
    emitStats(io);
  }
}

const { exec } = require('child_process');

function stopTshark() {
  capturing = false;

  if (tshark) {
    tshark.kill('SIGTERM');
    tshark = null;
  }

  // Fallback: kill all tshark processes
  exec('taskkill /IM tshark.exe /F', () => {});

  if (statsTimer) {
    clearInterval(statsTimer);
    statsTimer = null;
  }
}

module.exports = {
  start(iface = '5', filter = '', io) {
    if (capturing) {
      stopTshark();
    }
    resetStats();
    startTshark(io, iface, filter);
  },

  stop() {
    stopTshark();
  },

  isCapturing: () => capturing,
  getInterface: () => currentIface,
  getStats: () => ({ ...stats })
};