const express = require("express");
const http = require("http");
const cors = require("cors");
const { initSocket } = require("./socket");
const { startCapture } = require("./capture");

const app = express();
app.use(cors());

const server = http.createServer(app);

// 1. กำหนดค่าและเปิดใช้งาน Socket.io
const io = initSocket(server);

// 2. เริ่มการทำงานระบบดักจับ Packet และส่ง io instance เข้าไป
startCapture(io);

// 3. เริ่ม Server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});