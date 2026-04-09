const { analyzePacket } = require("./packetAnalyzer");

function startCapture(io) {
  console.log("📡 Starting packet capture simulation...");

  // จำลองการดักจับ (ตอนนี้ตั้งไว้ทุกๆ 20ms = 50 packets/sec)
  // หากต้องการเทสแบบ 1000 packets/sec ให้ลดตัวเลขด้านล่างลง
  setInterval(() => {
    const rawPacket = {
      id: Math.random().toString(36).substring(7),
      time: new Date().toLocaleTimeString(),
      srcIP: `192.168.1.${Math.floor(Math.random() * 255)}`,
      dstIP: `142.250.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      size: Math.floor(Math.random() * 1500) + 64, // ขนาด Byte (64 - 1564)
    };

    // 1. ส่งไปวิเคราะห์ และเตรียมบันทึก
    const finalPacket = analyzePacket(rawPacket);

    // 2. ยิงขึ้นหน้า Web แบบ Real-time ทันที
    io.emit("packet", finalPacket);

  }, 20); 
}

module.exports = { startCapture };