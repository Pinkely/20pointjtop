/**
 * packetCapture.js — Packet Capture & Analysis Module
 * ใช้ node-pcap สำหรับดักจับแพ็กเก็ตจริง
 * ถ้าไม่มี libpcap จะ fallback เป็น simulation mode
 */

let pcap;
try {
  pcap = require('pcap');
} catch {
  pcap = null; // simulation mode
}

// ── State ────────────────────────────────────────────────────────────────────
let session = null;
let capturing = false;
let currentIface = '';
let stats = {
  total: 0,
  encrypted: 0,
  unencrypted: 0,
  protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
  startTime: null
};
let simulationTimer = null;

// ── TLS Detection helpers ────────────────────────────────────────────────────
const TLS_PORTS = new Set([443, 8443, 465, 993, 995, 587]);
const SSH_PORTS = new Set([22]);
const DNS_PORTS = new Set([53]);

/**
 * ตรวจสอบ TLS version จาก payload bytes
 * TLS Record header: byte[0]=0x16 (handshake), byte[1-2]=version
 */
function detectTLS(payload) {
  if (!payload || payload.length < 6) return null;
  if (payload[0] !== 0x16) return null; // ไม่ใช่ TLS handshake

  const major = payload[1];
  const minor = payload[2];

  if (major === 0x03) {
    if (minor === 0x04) return 'TLS 1.3';
    if (minor === 0x03) return 'TLS 1.2';
    if (minor === 0x02) return 'TLS 1.1';
    if (minor === 0x01) return 'TLS 1.0';
    if (minor === 0x00) return 'SSL 3.0';
  }
  return 'TLS (unknown)';
}

/**
 * วิเคราะห์แพ็กเก็ตดิบ → structured packet object
 */
function analyzePacket(rawPacket) {
  try {
    const eth = rawPacket.payload;
    if (!eth || !eth.payload) return null;

    const ip = eth.payload;
    if (!ip.payload) return null;

    const transport = ip.payload;
    const srcIP = ip.saddr ? ip.saddr.toString() : '0.0.0.0';
    const dstIP = ip.daddr ? ip.daddr.toString() : '0.0.0.0';

    let proto = 'OTHER';
    let srcPort = 0, dstPort = 0;
    let tlsVersion = null;
    let encrypted = false;
    let size = rawPacket.pcap_header ? rawPacket.pcap_header.len : 0;

    // TCP
    if (transport.constructor && transport.constructor.name === 'TCP') {
      srcPort = transport.sport;
      dstPort = transport.dport;
      const payload = transport.data;

      if (TLS_PORTS.has(dstPort) || TLS_PORTS.has(srcPort)) {
        proto = 'HTTPS';
        tlsVersion = detectTLS(payload) || 'TLS 1.3';
        encrypted = true;
      } else if (SSH_PORTS.has(dstPort) || SSH_PORTS.has(srcPort)) {
        proto = 'SSH';
        tlsVersion = 'SSH-2.0';
        encrypted = true;
      } else if (dstPort === 80 || srcPort === 80) {
        proto = 'HTTP';
        encrypted = false;
      } else {
        proto = 'TCP';
        // ลองตรวจ TLS บน non-standard port
        tlsVersion = detectTLS(payload);
        encrypted = !!tlsVersion;
      }
    }
    // UDP
    else if (transport.constructor && transport.constructor.name === 'UDP') {
      srcPort = transport.sport;
      dstPort = transport.dport;

      if (DNS_PORTS.has(dstPort) || DNS_PORTS.has(srcPort)) {
        proto = 'DNS';
      } else {
        proto = 'UDP';
      }
    }
    // ICMP
    else {
      proto = 'ICMP';
    }

    return {
      id: ++stats.total,
      timestamp: new Date().toISOString(),
      time: new Date().toLocaleTimeString('th-TH'),
      srcIP,
      dstIP,
      srcPort,
      dstPort,
      protocol: proto,
      size,
      tlsVersion: tlsVersion || '-',
      encrypted,
      flags: transport.flags || {}
    };

  } catch (err) {
    return null;
  }
}

/**
 * อัปเดต stats และส่งผ่าน Socket.io
 */
function emitPacket(io, pkt) {
  if (!pkt) return;

  // อัปเดต stats
  if (pkt.encrypted) stats.encrypted++;
  else stats.unencrypted++;

  const p = pkt.protocol;
  if (stats.protocols[p] !== undefined) stats.protocols[p]++;
  else stats.protocols.OTHER++;

  // ส่งแพ็กเก็ตไปยัง clients ทั้งหมด
  io.emit('packet', pkt);

  // ส่ง stats สรุปทุก 50 แพ็กเก็ต
  if (stats.total % 50 === 0) emitStats(io);

  // ตรวจ security alerts
  checkAlerts(io, pkt);
}

/**
 * ส่ง stats summary
 */
function emitStats(io) {
  const elapsed = stats.startTime ? (Date.now() - stats.startTime) / 1000 : 1;
  io.emit('stats', {
    total: stats.total,
    encrypted: stats.encrypted,
    unencrypted: stats.unencrypted,
    encryptedPct: stats.total > 0 ? Math.round((stats.encrypted / stats.total) * 100) : 0,
    protocols: { ...stats.protocols },
    pps: Math.round(stats.total / elapsed),
    uptime: Math.round(elapsed)
  });
}

/**
 * ตรวจสอบ Security Alerts
 */
const alertCooldown = {};
function checkAlerts(io, pkt) {
  const now = Date.now();

  const alert = (id, type, message) => {
    if (alertCooldown[id] && now - alertCooldown[id] < 5000) return;
    alertCooldown[id] = now;
    io.emit('alert', { type, message, timestamp: new Date().toISOString() });
  };

  if (pkt.protocol === 'HTTP') {
    alert('http', 'danger', `พบการสื่อสาร HTTP ที่ไม่เข้ารหัส จาก ${pkt.srcIP}:${pkt.srcPort}`);
  }
  if (pkt.tlsVersion === 'SSL 3.0' || pkt.tlsVersion === 'TLS 1.0') {
    alert('oldtls', 'warning', `พบ ${pkt.tlsVersion} ที่มีช่องโหว่ (${pkt.srcIP} → ${pkt.dstIP})`);
  }
  if (pkt.protocol === 'TCP' && pkt.dstPort < 1024 && !pkt.encrypted) {
    alert('portscan', 'warning', `พบการเชื่อมต่อ port ต่ำ ${pkt.dstPort} จาก ${pkt.srcIP}`);
  }
}

// ── Simulation Mode (ไม่มี libpcap) ─────────────────────────────────────────
const SIM_PROTOCOLS = [
  { proto: 'HTTPS', port: 443, enc: true, tls: 'TLS 1.3' },
  { proto: 'HTTPS', port: 443, enc: true, tls: 'TLS 1.2' },
  { proto: 'HTTPS', port: 443, enc: true, tls: 'TLS 1.3' },
  { proto: 'HTTP',  port: 80,  enc: false, tls: null },
  { proto: 'DNS',   port: 53,  enc: false, tls: null },
  { proto: 'SSH',   port: 22,  enc: true,  tls: 'SSH-2.0' },
  { proto: 'TCP',   port: 8080, enc: false, tls: null },
  { proto: 'HTTPS', port: 8443, enc: true,  tls: 'TLS 1.3' },
];
const IP_POOL = ['192.168.1.','10.0.0.','172.16.0.'];
function rIP(p) { return p[Math.floor(Math.random()*p.length)] + (Math.floor(Math.random()*250)+2); }

function startSimulation(io) {
  console.log('🔧 Simulation mode: จำลองแพ็กเก็ต (ไม่มี libpcap)');
  simulationTimer = setInterval(() => {
    const burst = Math.floor(Math.random() * 12) + 2;
    for (let i = 0; i < burst; i++) {
      const tmpl = SIM_PROTOCOLS[Math.floor(Math.random() * SIM_PROTOCOLS.length)];
      const pkt = {
        id: ++stats.total,
        timestamp: new Date().toISOString(),
        time: new Date().toLocaleTimeString('th-TH'),
        srcIP: rIP(IP_POOL),
        dstIP: rIP(IP_POOL),
        srcPort: Math.floor(Math.random() * 60000) + 1024,
        dstPort: tmpl.port,
        protocol: tmpl.proto,
        size: Math.floor(Math.random() * 1400) + 40,
        tlsVersion: tmpl.tls || '-',
        encrypted: tmpl.enc
      };
      if (pkt.encrypted) stats.encrypted++; else stats.unencrypted++;
      const p = pkt.protocol;
      if (stats.protocols[p] !== undefined) stats.protocols[p]++;
      io.emit('packet', pkt);
      checkAlerts(io, pkt);
    }
    emitStats(io);
  }, 800);
}

// ── Public API ────────────────────────────────────────────────────────────────
module.exports = {
  start(iface, filter, io) {
    if (capturing) this.stop();

    // Reset stats
    stats = {
      total: 0, encrypted: 0, unencrypted: 0,
      protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
      startTime: Date.now()
    };
    currentIface = iface;
    capturing = true;

    if (!pcap) {
      startSimulation(io);
      return;
    }

    // Real capture
    const bpfFilter = filter || 'ip';
    session = pcap.createSession(iface, { filter: bpfFilter, buffer_size: 4 * 1024 * 1024 });

    session.on('packet', (rawPacket) => {
      const pkt = analyzePacket(rawPacket);
      emitPacket(io, pkt);
    });

    session.on('error', (err) => {
      io.emit('error', { message: `Capture error: ${err.message}` });
    });

    // ส่ง stats ทุก 2 วินาที
    this._statsTimer = setInterval(() => emitStats(io), 2000);
  },

  stop() {
    capturing = false;
    if (session) { try { session.close(); } catch {} session = null; }
    if (simulationTimer) { clearInterval(simulationTimer); simulationTimer = null; }
    if (this._statsTimer) { clearInterval(this._statsTimer); }
  },

  isCapturing: () => capturing,
  getInterface: () => currentIface,
  getStats: () => ({ ...stats })
};
