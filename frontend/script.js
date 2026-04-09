// ── Config ────────────────────────────────────────────────────────────────────
const socket = io('http://localhost:3000');

const username = sessionStorage.getItem('username') || 'guest';
const role     = sessionStorage.getItem('role')     || 'user';

// ── State ─────────────────────────────────────────────────────────────────────
let running = false;
let totalPkts = 0, encPkts = 0, noencPkts = 0;
let packets = [];
const MAX_ROWS = 15;
let currentFilter = 'ALL';
const protoCounts = { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };

// ── Charts ────────────────────────────────────────────────────────────────────
const chartOptions = {
  responsive: true, maintainAspectRatio: false, animation: false,
  plugins: { legend: { display: false } }
};

const lineChart = new Chart(document.getElementById('lineChart').getContext('2d'), {
  type: 'line',
  data: {
    labels: Array(30).fill(''),
    datasets: [{ data: Array(30).fill(0), borderColor: '#3b82f6',
      backgroundColor: 'rgba(59,130,246,0.1)', fill: true, tension: 0.4,
      borderWidth: 2, pointRadius: 0 }]
  },
  options: chartOptions
});

const donutChart = new Chart(document.getElementById('donutChart').getContext('2d'), {
  type: 'doughnut',
  data: {
    labels: ['Encrypted', 'Unencrypted'],
    datasets: [{ data: [0, 0], backgroundColor: ['#10b981', '#ef4444'],
      borderWidth: 0, cutout: '75%' }]
  },
  options: chartOptions
});

const barChart = new Chart(document.getElementById('barChart').getContext('2d'), {
  type: 'bar',
  data: {
    labels: Object.keys(protoCounts),
    datasets: [{ data: Object.values(protoCounts), backgroundColor: '#6366f1', borderRadius: 4 }]
  },
  options: chartOptions
});

// ── Socket.io Events ──────────────────────────────────────────────────────────
socket.on('connect', () => {
  socket.emit('auth', { username, role });
});

socket.on('connected', (data) => {
  running = data.capturing;
  updateToggleBtn();
  addAlert('info', `เชื่อมต่อสำเร็จ (${data.role}: ${data.username})`);
});

socket.on('packet', (pkt) => {
  packets = [pkt, ...packets].slice(0, 50);
  totalPkts++;
  if (pkt.encrypted) encPkts++; else noencPkts++;
  if (protoCounts[pkt.protocol] !== undefined) protoCounts[pkt.protocol]++;
  else protoCounts['OTHER']++;
  updateStats(1);
  renderTable();
  updateCharts(1);
});

socket.on('stats', (s) => {
  totalPkts  = s.total;   encPkts    = s.encrypted;   noencPkts  = s.unencrypted;
  Object.assign(protoCounts, s.protocols || {});
  const ep = s.encryptedPct || 0;
  document.getElementById('total').textContent       = totalPkts.toLocaleString();
  document.getElementById('enc-pct').textContent     = ep + '%';
  document.getElementById('noenc-pct').textContent   = (100 - ep) + '%';
  document.getElementById('enc-count').textContent   = encPkts.toLocaleString() + ' pkts';
  document.getElementById('noenc-count').textContent = noencPkts.toLocaleString() + ' pkts';
  donutChart.data.datasets[0].data = [encPkts, noencPkts];
  donutChart.update('none');
  barChart.data.datasets[0].data = Object.values(protoCounts);
  barChart.update('none');
});

socket.on('alert', (a) => {
  const who = a.owner && role === 'admin' ? ` [${a.owner}]` : '';
  addAlert(a.type, a.message + who);
});

socket.on('capture:status', (s) => {
  running = s.capturing;
  updateToggleBtn();
});

socket.on('error', (e) => addAlert('danger', e.message));

// ── UI Controls ───────────────────────────────────────────────────────────────
function toggleCapture() {
  if (!running) {
    socket.emit('capture:start', { iface: 'eth0', filter: '' });
  } else {
    socket.emit('capture:stop');
  }
}

function updateToggleBtn() {
  const btn = document.getElementById('toggleBtn');
  if (!btn) return;
  btn.textContent = running ? 'หยุดดักจับ' : 'เริ่มดักจับ';
  btn.style.background = running ? '#fff' : '#3b82f6';
  btn.style.color = running ? '#1e293b' : '#fff';
}

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}

// ── Render ────────────────────────────────────────────────────────────────────
function renderTable() {
  const tbody = document.getElementById('packet-table');
  if (!tbody) return;
  const filtered = currentFilter === 'ALL' ? packets : packets.filter(p => p.protocol === currentFilter);
  const ownerCol = role === 'admin';
  tbody.innerHTML = filtered.slice(0, MAX_ROWS).map(p => `
    <tr>
      <td>#${p.id}</td>
      <td>${p.time || new Date(p.timestamp).toLocaleTimeString('th-TH')}</td>
      ${ownerCol ? `<td><b>${p.owner || '-'}</b></td>` : ''}
      <td>${p.srcIP}</td><td>${p.dstIP}</td>
      <td><span class="pill pill-${(p.protocol||'').toLowerCase()}">${p.protocol}</span></td>
      <td>${p.dstPort || '-'}</td><td>${p.size}</td>
      <td style="color:var(--text-sub)">${p.tlsVersion || '-'}</td>
      <td><span class="pill ${p.encrypted ? 'pill-enc' : 'pill-noenc'}">
        ${p.encrypted ? 'Encrypted' : 'Unencrypted'}</span></td>
    </tr>
  `).join('');
}

function updateStats(burst) {
  const ep = totalPkts > 0 ? Math.round((encPkts / totalPkts) * 100) : 0;
  document.getElementById('pps').textContent        = burst;
  document.getElementById('total').textContent      = totalPkts.toLocaleString();
  document.getElementById('enc-pct').textContent    = ep + '%';
  document.getElementById('noenc-pct').textContent  = (100 - ep) + '%';
  document.getElementById('enc-count').textContent  = encPkts.toLocaleString() + ' pkts';
  document.getElementById('noenc-count').textContent = noencPkts.toLocaleString() + ' pkts';
}

function updateCharts(burst) {
  lineChart.data.datasets[0].data.push(burst);
  lineChart.data.datasets[0].data.shift();
  lineChart.update('none');
  donutChart.data.datasets[0].data = [encPkts, noencPkts];
  donutChart.update('none');
  barChart.data.datasets[0].data = Object.values(protoCounts);
  barChart.update('none');
}

function addAlert(type, msg) {
  const box = document.getElementById('alerts-box');
  if (!box) return;
  const icon = type === 'danger' ? '✕' : type === 'warning' ? '⚠' : 'ℹ';
  box.insertAdjacentHTML('afterbegin', `
    <div class="alert-row alert-${type}">
      <span>${icon}</span>
      <div>${msg}<br><small>${new Date().toLocaleTimeString()}</small></div>
    </div>`);
  if (box.children.length > 5) box.lastElementChild.remove();
}

function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('th-TH');
}

// ── Init ──────────────────────────────────────────────────────────────────────
setInterval(updateClock, 1000);
updateClock();
const roleEl = document.getElementById('user-role-display');
if (roleEl) roleEl.textContent = `${username} (${role})`;