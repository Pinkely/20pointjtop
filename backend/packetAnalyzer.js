const fs = require("fs");
const path = require("path");

const PACKET_FILE = path.join(__dirname, "packet.json");
let packetBuffer = [];
const BATCH_SIZE = 500; // สะสมครบ 500 packets ค่อยเขียนลงไฟล์ 1 ครั้ง

// สร้างไฟล์เปล่าเตรียมไว้ถ้ายังไม่มี
if (!fs.existsSync(PACKET_FILE)) {
  fs.writeFileSync(PACKET_FILE, "[]");
}

function analyzePacket(rawPacket) {
  // 1. วิเคราะห์ Protocol และตรวจสอบการเข้ารหัส (จำลอง Logic)
  const protocols = ["TCP", "UDP", "HTTP", "HTTPS", "TLSv1.3", "QUIC"];
  const protocol = protocols[Math.floor(Math.random() * protocols.length)];
  const isEncrypted = ["HTTPS", "TLSv1.3", "QUIC"].includes(protocol);

  const analyzedPacket = {
    ...rawPacket,
    protocol: protocol,
    encrypted: isEncrypted,
    analyzedAt: new Date().toISOString()
  };

  // 2. เก็บลง Buffer 
  packetBuffer.push(analyzedPacket);

  // 3. ถ้า Buffer เต็ม ค่อยสั่งเขียนลงไฟล์ JSON (ลดภาระ Disk I/O)
  if (packetBuffer.length >= BATCH_SIZE) {
    saveBatchToFile([...packetBuffer]); 
    packetBuffer = []; // เคลียร์ buffer เริ่มเก็บใหม่
  }

  return analyzedPacket; // คืนค่า packet ที่วิเคราะห์แล้วเอาไปส่งต่อ
}

function saveBatchToFile(batchData) {
  fs.readFile(PACKET_FILE, "utf8", (err, data) => {
    if (err) return console.error("Read Error:", err);
    
    let currentData = [];
    try {
      currentData = JSON.parse(data || "[]");
    } catch(e) {
      currentData = [];
    }

    // ต่อข้อมูลใหม่เข้าไป (Limit ไว้ที่ 20,000 records ล่าสุด เพื่อไม่ให้ไฟล์ใหญ่เกินไป)
    currentData = currentData.concat(batchData).slice(-20000);

    fs.writeFile(PACKET_FILE, JSON.stringify(currentData, null, 2), (err) => {
      if (err) console.error("Write Error:", err);
      else console.log(`💾 Saved ${batchData.length} packets to JSON.`);
    });
  });
}

module.exports = { analyzePacket };