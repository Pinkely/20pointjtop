// server.js
const express = require("express");
const http    = require("http");
const cors    = require("cors");
const path    = require("path");
const { Server } = require("socket.io");
const packetCapture = require("./capture");
const authRoutes    = require("./routes/authRoutes");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Auth API routes
app.use("/api", authRoutes);

const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

// ── Socket.io event handling ───────────────────────────────────────────────────
io.on("connection", (socket) => {
  console.log(`[socket] client connected: ${socket.id}`);

  // Send current state to new client
  socket.emit("connected", {
    capturing: packetCapture.isCapturing(),
    interface: packetCapture.getInterface(),
    config:    packetCapture.getConfig(),
  });

  // ── Start capture ──────────────────────────────────────────
  socket.on("capture:start", ({ iface = "5", filter = "" } = {}) => {
    console.log(`[socket] capture:start iface=${iface} filter=${filter}`);
    packetCapture.start(iface, filter, io);
  });

  // ── Stop capture ───────────────────────────────────────────
  socket.on("capture:stop", () => {
    console.log("[socket] capture:stop");
    packetCapture.stop();
    io.emit("capture:status", { capturing: false });
  });

  // ── Runtime config (bufferSize / promiscuous) ──────────────
  socket.on("capture:config", (config = {}) => {
    console.log("[socket] capture:config", config);
    packetCapture.applyConfig(config, io);
  });

  socket.on("disconnect", () => {
    console.log(`[socket] client disconnected: ${socket.id}`);
  });
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🔐 Auth API ready at http://localhost:${PORT}/api`);
});