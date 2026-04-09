/**
 * socketHandler.js — Socket.io Event Handler
 * จัดการ events ทั้งหมดระหว่าง Server ↔ Client
 */

module.exports = function socketHandler(io, packetCapture) {
  // นับ connections
  let connectionCount = 0;

  io.on('connection', (socket) => {
    connectionCount++;
    const clientIP = socket.handshake.address;
    console.log(`🔌 Client เชื่อมต่อ: ${socket.id} (${clientIP}) — รวม ${connectionCount} connections`);

    // ── ส่งข้อมูลเริ่มต้นให้ client ──────────────────────────────────────────
    socket.emit('connected', {
      message: 'เชื่อมต่อ WebSocket สำเร็จ',
      socketId: socket.id,
      serverTime: new Date().toISOString(),
      capturing: packetCapture.isCapturing(),
      interface: packetCapture.getInterface()
    });

    // ส่ง stats ปัจจุบันทันที
    socket.emit('stats', buildStats(packetCapture));

    // ── Events รับจาก Client ─────────────────────────────────────────────────

    // Client ขอเริ่มดักจับ
    socket.on('capture:start', ({ iface = 'eth0', filter = '' } = {}) => {
      console.log(`▶  capture:start — iface=${iface} filter="${filter}"`);
      try {
        packetCapture.start(iface, filter, io);
        io.emit('capture:status', { capturing: true, interface: iface });
      } catch (err) {
        socket.emit('error', { message: err.message });
      }
    });

    // Client ขอหยุดดักจับ
    socket.on('capture:stop', () => {
      console.log('⏹  capture:stop');
      packetCapture.stop();
      io.emit('capture:status', { capturing: false });
    });

    // Client ขอ stats ล่าสุด
    socket.on('stats:request', () => {
      socket.emit('stats', buildStats(packetCapture));
    });

    // Client ขอ ping (ตรวจ latency)
    socket.on('ping', (data) => {
      socket.emit('pong', { ...data, serverTime: Date.now() });
    });

    // ── Disconnect ────────────────────────────────────────────────────────────
    socket.on('disconnect', (reason) => {
      connectionCount = Math.max(0, connectionCount - 1);
      console.log(`❌ Client ตัดการเชื่อมต่อ: ${socket.id} (${reason}) — เหลือ ${connectionCount} connections`);
    });

    // ── Error ─────────────────────────────────────────────────────────────────
    socket.on('error', (err) => {
      console.error(`⚠️  Socket error (${socket.id}):`, err.message);
    });
  });

  // Log จำนวน connections ทุก 30 วินาที
  setInterval(() => {
    if (connectionCount > 0) {
      console.log(`📊 Active connections: ${connectionCount}`);
    }
  }, 30000);
};

function buildStats(packetCapture) {
  const s = packetCapture.getStats();
  return {
    total: s.total,
    encrypted: s.encrypted,
    unencrypted: s.unencrypted,
    encryptedPct: s.total > 0 ? Math.round((s.encrypted / s.total) * 100) : 0,
    protocols: s.protocols || {},
    uptime: s.startTime ? Math.round((Date.now() - s.startTime) / 1000) : 0
  };
}
