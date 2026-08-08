/**
 * AegisFlow Dashboard — Client-Side Logic
 *
 * Polls /aegisflow/stats and /aegisflow/logs every 2 seconds.
 * Renders live feed, Chart.js charts, Leaflet map, and integrity verification.
 */

// ============================================================
// State
// ============================================================
let categoryChart = null;
let decisionChart = null;
let leafletMap = null;
let mapMarkers = [];
let previousLogIds = new Set();
let isFirstLoad = true;
const POLL_INTERVAL = 2000;

// IP → Exact location cache
const exactLocations = {
  "185.220.101.34": { lat: 55.7558, lng: 37.6173 },
  "103.152.220.44": { lat: 39.9042, lng: 116.4074 },
  "45.33.32.156": { lat: 37.5485, lng: -121.9886 },
  "198.51.100.73": { lat: 51.5074, lng: -0.1278 },
  "203.0.113.42": { lat: 35.6762, lng: 139.6503 },
  "91.234.99.87": { lat: 50.4501, lng: 30.5234 },
  "177.54.150.200": { lat: -23.5505, lng: -46.6333 },
  "41.76.108.14": { lat: 6.5244, lng: 3.3792 },
  "156.146.56.78": { lat: 19.0760, lng: 72.8777 },
  "31.13.72.36": { lat: 53.3498, lng: -6.2603 },
  "77.88.55.70": { lat: 52.3676, lng: 4.9041 },
  "104.244.42.65": { lat: 37.7749, lng: -122.4194 },
  "88.198.0.44": { lat: 52.5200, lng: 13.4050 },
  "5.161.76.19": { lat: 1.3521, lng: 103.8198 },
  "196.216.2.13": { lat: -33.9249, lng: 18.4241 },
  "200.7.4.7": { lat: -34.6037, lng: -58.3816 }
};

function ipToExactLatLng(ip) {
  if (exactLocations[ip]) return exactLocations[ip];

  // Deterministic seed from IP string
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = ((hash << 5) - hash + ip.charCodeAt(i)) | 0;
  }

  const seededRandom1 = ((Math.abs(hash * 2654435761) % 1000) / 1000) - 0.5;
  const seededRandom2 = ((Math.abs(hash * 2246822519) % 1000) / 1000) - 0.5;

  return {
    lat: 30 + seededRandom1 * 20,
    lng: 10 + seededRandom2 * 20,
  };
}

function formatTime(isoString) {
  const d = new Date(isoString);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function scoreClass(score) {
  if (score >= 60) return 'high';
  if (score >= 30) return 'mid';
  return 'low';
}

function decisionBadge(decision) {
  const cls = decision === 'allow' ? 'allow' : decision === 'rate-limit' ? 'rate-limit' : 'block';
  const icon = decision === 'allow' ? '✓' : decision === 'rate-limit' ? '⏱' : '✕';
  return `<span class="badge badge--${cls}">${icon} ${decision}</span>`;
}

function methodClass(method) {
  return `feed__method feed__method--${method}`;
}

// ============================================================
// Stats
// ============================================================

async function fetchStats() {
  try {
    const res = await fetch('/aegisflow/stats');
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    console.warn('Failed to fetch stats:', e);
    return null;
  }
}

function updateStats(stats) {
  if (!stats) return;

  const el = (id) => document.getElementById(id);

  // Animate number changes
  animateValue(el('stat-total'), stats.total);
  animateValue(el('stat-allowed'), stats.byDecision?.allow || 0);
  animateValue(el('stat-rate-limited'), stats.byDecision?.['rate-limit'] || 0);
  animateValue(el('stat-blocked'), stats.byDecision?.block || 0);
}

function animateValue(el, newVal) {
  if (!el) return;
  const current = parseInt(el.textContent) || 0;
  if (current === newVal) return;

  el.textContent = newVal;
  el.style.transform = 'scale(1.15)';
  el.style.transition = 'transform 0.2s ease';
  setTimeout(() => {
    el.style.transform = 'scale(1)';
  }, 200);
}

// ============================================================
// Charts
// ============================================================

const chartColors = {
  clean: '#34d399',
  sqli: '#f87171',
  xss: '#fb923c',
  vpn: '#a78bfa',
  recon: '#fbbf24',
  bruteforce: '#f472b6',
  // AegisFlow Specific
  Clean: '#34d399',
  SqlInjection: '#ef4444',
  XSS: '#f97316',
  PromptInjection: '#8b5cf6',
  PathTraversal: '#eab308',
  CredentialStuffing: '#ec4899',
  RateLimited: '#fbbf24',
  AI_DOM_AGENT: '#0ea5e9',
};

const decisionColors = {
  allow: '#34d399',
  'rate-limit': '#fbbf24',
  block: '#f87171',
};

function initCharts() {
  // Category donut chart
  const catCtx = document.getElementById('category-chart')?.getContext('2d');
  if (catCtx) {
    categoryChart = new Chart(catCtx, {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: [],
          borderColor: 'rgba(6, 6, 15, 0.8)',
          borderWidth: 2,
          hoverOffset: 8,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#94a3b8',
              font: { family: "'Inter', sans-serif", size: 11, weight: '500' },
              padding: 12,
              usePointStyle: true,
              pointStyleWidth: 10,
            },
          },
          tooltip: {
            backgroundColor: 'rgba(15, 15, 35, 0.9)',
            titleColor: '#f1f5f9',
            bodyColor: '#94a3b8',
            borderColor: 'rgba(255, 255, 255, 0.06)',
            borderWidth: 1,
            cornerRadius: 8,
            titleFont: { family: "'Inter', sans-serif", weight: '600' },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 12 },
            padding: 12,
          },
        },
        animation: {
          animateRotate: true,
          duration: 600,
        },
      },
    });
  }

  // Decision bar chart
  const decCtx = document.getElementById('decision-chart')?.getContext('2d');
  if (decCtx) {
    decisionChart = new Chart(decCtx, {
      type: 'bar',
      data: {
        labels: ['Allow', 'Rate-Limit', 'Block'],
        datasets: [{
          label: 'Requests',
          data: [0, 0, 0],
          backgroundColor: [
            'rgba(52, 211, 153, 0.6)',
            'rgba(251, 191, 36, 0.6)',
            'rgba(248, 113, 113, 0.6)',
          ],
          borderColor: [
            'rgba(52, 211, 153, 1)',
            'rgba(251, 191, 36, 1)',
            'rgba(248, 113, 113, 1)',
          ],
          borderWidth: 1,
          borderRadius: 6,
          borderSkipped: false,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: '#94a3b8',
              font: { family: "'Inter', sans-serif", size: 11, weight: '500' },
            },
          },
          y: {
            grid: {
              color: 'rgba(255, 255, 255, 0.03)',
              drawBorder: false,
            },
            ticks: {
              color: '#64748b',
              font: { family: "'JetBrains Mono', monospace", size: 11 },
              stepSize: 1,
            },
            beginAtZero: true,
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(15, 15, 35, 0.9)',
            titleColor: '#f1f5f9',
            bodyColor: '#94a3b8',
            borderColor: 'rgba(255, 255, 255, 0.06)',
            borderWidth: 1,
            cornerRadius: 8,
            titleFont: { family: "'Inter', sans-serif", weight: '600' },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 12 },
            padding: 12,
          },
        },
        animation: {
          duration: 400,
        },
      },
    });
  }
}

function updateCharts(stats) {
  if (!stats) return;

  // Category chart
  if (categoryChart && stats.byCategory) {
    const labels = Object.keys(stats.byCategory);
    const data = Object.values(stats.byCategory);
    const colors = labels.map((l) => chartColors[l] || '#64748b');

    categoryChart.data.labels = labels.map((l) => l.charAt(0).toUpperCase() + l.slice(1));
    categoryChart.data.datasets[0].data = data;
    categoryChart.data.datasets[0].backgroundColor = colors;
    categoryChart.update('none');
  }

  // Decision chart
  if (decisionChart && stats.byDecision) {
    decisionChart.data.datasets[0].data = [
      stats.byDecision.allow || 0,
      stats.byDecision['rate-limit'] || 0,
      stats.byDecision.block || 0,
    ];
    decisionChart.update('none');
  }
}

// ============================================================
// Leaflet Map
// ============================================================

function initMap() {
  const mapEl = document.getElementById('threat-map');
  if (!mapEl) return;

  leafletMap = L.map('threat-map', {
    center: [30, 10],
    zoom: 2,
    minZoom: 2,
    maxZoom: 10,
    zoomControl: true,
    attributionControl: false,
  });

  L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
    maxZoom: 19,
    attribution: 'Tiles &copy; Esri'
  }).addTo(leafletMap);
}

function updateMap(logs) {
  if (!leafletMap || !logs) return;

  // Clear old markers
  mapMarkers.forEach((m) => leafletMap.removeLayer(m));
  mapMarkers = [];

  // Add markers for recent unique IPs
  const seenIPs = new Set();
  for (const log of logs.slice(0, 30)) {
    if (seenIPs.has(log.ip)) continue;
    seenIPs.add(log.ip);

    const coords = ipToExactLatLng(log.ip);
    const color = log.decision === 'block' ? '#f87171'
      : log.decision === 'rate-limit' ? '#fbbf24'
      : '#34d399';

    const marker = L.circleMarker([coords.lat, coords.lng], {
      radius: log.decision === 'block' ? 7 : 5,
      fillColor: color,
      color: color,
      weight: 1,
      opacity: 0.9,
      fillOpacity: 0.7,
    });

    marker.bindPopup(`
      <div style="min-width: 160px">
        <div style="color: ${color}; font-weight: 600; margin-bottom: 4px;">
          ${log.decision.toUpperCase()} — Score ${log.score}
        </div>
        <div>IP: ${log.ip}</div>
        <div>${log.method} ${log.path}</div>
        <div style="color: #64748b; margin-top: 4px;">${log.category}</div>
      </div>
    `);

    marker.addTo(leafletMap);
    mapMarkers.push(marker);
  }
}

// ============================================================
// Live Feed
// ============================================================

async function fetchLogs() {
  try {
    const res = await fetch('/aegisflow/logs?limit=20');
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    console.warn('Failed to fetch logs:', e);
    return null;
  }
}

function updateFeed(data) {
  if (!data || !data.logs) return;

  const tbody = document.getElementById('feed-body');
  if (!tbody) return;

  const newIds = new Set(data.logs.map((l) => l.id));

  tbody.innerHTML = data.logs
    .map((log) => {
      const isNew = !isFirstLoad && !previousLogIds.has(log.id);
      return `
        <tr class="${isNew ? 'row--new' : ''}">
          <td class="feed__time">${formatTime(log.timestamp)}</td>
          <td><span class="${methodClass(log.method)}">${log.method}</span></td>
          <td class="feed__path" title="${escapeHtml(log.path)}">${escapeHtml(log.path)}</td>
          <td class="feed__ip">${log.ip}</td>
          <td class="feed__score feed__score--${scoreClass(log.score)}">${log.score}</td>
          <td><span class="category-badge">${log.category}</span></td>
          <td>${decisionBadge(log.decision)}</td>
        </tr>
      `;
    })
    .join('');

  previousLogIds = newIds;
  isFirstLoad = false;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ============================================================
// Verify Integrity
// ============================================================

async function verifyIntegrity() {
  const btn = document.getElementById('verify-btn');
  const result = document.getElementById('verify-result');
  if (!btn || !result) return;

  // Loading state
  btn.classList.add('verify-btn--loading');
  btn.disabled = true;
  result.classList.remove('verify-result--visible', 'verify-result--intact', 'verify-result--tampered');

  try {
    // Artificial small delay for dramatic effect
    await new Promise((r) => setTimeout(r, 800));

    const res = await fetch('/aegisflow/verify');
    const data = await res.json();

    if (data.intact) {
      result.innerHTML = `
        <span class="verify-result__icon">✓</span>
        <div>
          <div style="font-weight: 700;">CHAIN INTACT</div>
          <div style="font-size: 0.75rem; opacity: 0.7;">All log entries verified • ${data.verifiedAt ? formatTime(data.verifiedAt) : ''}</div>
        </div>
      `;
      result.className = 'verify-result verify-result--visible verify-result--intact';
    } else {
      result.innerHTML = `
        <span class="verify-result__icon">⚠</span>
        <div>
          <div style="font-weight: 700;">TAMPERED — INTEGRITY COMPROMISED</div>
          <div style="font-size: 0.75rem; opacity: 0.7;">Hash chain verification failed at Log ID: ${data.failedAtId || 'Unknown'}</div>
        </div>
      `;
      result.className = 'verify-result verify-result--visible verify-result--tampered';
    }
  } catch (e) {
    result.innerHTML = `
      <span class="verify-result__icon">⚠</span>
      <div>
        <div style="font-weight: 700;">VERIFICATION ERROR</div>
        <div style="font-size: 0.75rem; opacity: 0.7;">${e.message}</div>
      </div>
    `;
    result.className = 'verify-result verify-result--visible verify-result--tampered';
  } finally {
    btn.classList.remove('verify-btn--loading');
    btn.disabled = false;
  }
}

async function resetChain() {
  const btn = document.getElementById('reset-chain-btn');
  const result = document.getElementById('verify-result');
  if (!btn || !result) return;
  
  btn.disabled = true;
  try {
    await fetch('/aegisflow/verify/reset', { method: 'POST' });
    result.innerHTML = `
        <span class="verify-result__icon">✓</span>
        <div>
          <div style="font-weight: 700;">CHAIN RESET</div>
          <div style="font-size: 0.75rem; opacity: 0.7;">Hash chain has been successfully restarted.</div>
        </div>
      `;
    result.className = 'verify-result verify-result--visible verify-result--intact';
    
    // Clear local cache to force refresh
    previousLogIds.clear();
    isFirstLoad = true;
  } catch (e) {
    result.innerHTML = `
      <span class="verify-result__icon">⚠</span>
      <div>
        <div style="font-weight: 700;">RESET ERROR</div>
        <div style="font-size: 0.75rem; opacity: 0.7;">${e.message}</div>
      </div>
    `;
    result.className = 'verify-result verify-result--visible verify-result--tampered';
  } finally {
    btn.disabled = false;
  }
}

// ============================================================
// Data Leak Exfiltration Console
// ============================================================

async function fetchLeaks() {
  try {
    const res = await fetch('/aegisflow/leaks');
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

function updateLeaks(leakData) {
  const container = document.getElementById('leak-feed-container');
  const badge = document.getElementById('leak-count-badge');
  if (!container || !badge) return;

  const leaks = leakData?.leaks || [];
  const count = leakData?.totalLeaks || leaks.length;

  if (count === 0) {
    badge.textContent = `0 Data Leaks Detected`;
    badge.style.background = 'rgba(52,211,153,0.15)';
    badge.style.color = '#34d399';
    badge.style.borderColor = 'rgba(52,211,153,0.3)';
    container.innerHTML = `
      <div style="text-align: center; color: var(--color-allow); padding: 24px;">
        🛡 <strong>0 Data Leaks</strong> — WAF Protection active or no successful exfiltrations recorded.
      </div>
    `;
    return;
  }

  badge.textContent = `🚨 ${count} Data Leaks Recorded`;
  badge.style.background = 'rgba(239,68,68,0.2)';
  badge.style.color = '#f87171';
  badge.style.borderColor = 'rgba(239,68,68,0.4)';

  container.innerHTML = leaks.map(leak => `
    <div style="background: rgba(239,68,68,0.06); border: 1px solid rgba(239,68,68,0.2); border-radius: 8px; padding: 12px; margin-bottom: 10px;">
      <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-weight: 700; color: #f87171;">
        <span>💥 VECTOR: ${escapeHtml(leak.vector)}</span>
        <span style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(leak.timestamp)}</span>
      </div>
      <div style="margin-bottom: 6px; color: var(--text-subtle);">
        <strong style="color: var(--accent-cyan);">Payload Sent:</strong> <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">${escapeHtml(leak.payload)}</code>
      </div>
      <div style="color: #fca5a5;">
        <strong style="color: #f87171;">Exfiltrated Stolen Data:</strong>
        <pre style="background: rgba(0,0,0,0.5); padding: 8px; border-radius: 6px; margin-top: 4px; overflow-x: auto; font-size: 0.75rem; border: 1px dashed rgba(239,68,68,0.3); max-height: 120px;">${escapeHtml(JSON.stringify(leak.stolenData, null, 2))}</pre>
      </div>
    </div>
  `).join('');
}

async function clearLeaks() {
  try {
    await fetch('/aegisflow/leaks/clear', { method: 'POST' });
    updateLeaks({ totalLeaks: 0, leaks: [] });
  } catch (e) {}
}

// ============================================================
// Polling Loop
// ============================================================

async function poll() {
  const [stats, logData, leakData] = await Promise.all([fetchStats(), fetchLogs(), fetchLeaks()]);

  updateStats(stats);
  updateCharts(stats);
  updateFeed(logData);
  updateMap(logData?.logs);
  updateLeaks(leakData);
}

// ============================================================
// Init
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  initMap();

  // Wire up verify button
  const verifyBtn = document.getElementById('verify-btn');
  if (verifyBtn) {
    verifyBtn.addEventListener('click', verifyIntegrity);
  }

  // Wire up reset chain button
  const resetBtn = document.getElementById('reset-chain-btn');
  if (resetBtn) {
    resetBtn.addEventListener('click', resetChain);
  }

  // Wire up clear leaks button
  const clearLeaksBtn = document.getElementById('clear-leaks-btn');
  if (clearLeaksBtn) {
    clearLeaksBtn.addEventListener('click', clearLeaks);
  }

  // Wire up WAF toggle
  initWafToggle();

  // Start GPS telemetry
  initGeoTelemetry();

  // Initial poll
  poll();

  // Start polling every 2 seconds
  setInterval(poll, POLL_INTERVAL);
});

// ============================================================
// WAF Toggle
// ============================================================

async function initWafToggle() {
  const input = document.getElementById('waf-toggle-input');
  if (!input) return;

  // Fetch current state
  try {
    const res = await fetch('/aegisflow/toggle');
    if (res.ok) {
      const data = await res.json();
      input.checked = data.enabled;
      updateWafToggleUI(data.enabled);
    }
  } catch (e) {}

  input.addEventListener('change', async () => {
    const enabled = input.checked;
    try {
      const res = await fetch('/aegisflow/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      const data = await res.json();
      updateWafToggleUI(data.enabled);
    } catch (e) {
      console.warn('WAF toggle failed:', e);
      input.checked = !enabled; // revert on failure
    }
  });
}

function updateWafToggleUI(enabled) {
  const badge   = document.getElementById('waf-badge');
  const icon    = document.getElementById('waf-badge-icon');
  const text    = document.getElementById('waf-badge-text');
  const input   = document.getElementById('waf-toggle-input');

  if (input) input.checked = enabled;

  if (enabled) {
    if (badge) badge.className = 'waf-badge waf-badge--on';
    if (icon)  icon.textContent = '🛡';
    if (text)  text.textContent = 'ACTIVE SHIELD (PROTECTED)';
  } else {
    if (badge) badge.className = 'waf-badge waf-badge--off';
    if (icon)  icon.textContent = '⚠️';
    if (text)  text.textContent = 'SHIELD DISABLED (VULNERABLE)';
  }
}

// ============================================================
// GPS / Geo-Telemetry
// ============================================================

const GEO_TRAIL_MAX = 10;
const geoTrail = [];

function initGeoTelemetry() {
  if (!('geolocation' in navigator)) {
    updateGeoStatus('GPS not supported by this browser');
    return;
  }

  updateGeoStatus('Requesting location permission…');

  navigator.geolocation.getCurrentPosition(
    (pos) => onGeoSuccess(pos),
    (err) => onGeoError(err),
    { enableHighAccuracy: true, timeout: 10000 }
  );

  // Watch continuously for live tracking
  navigator.geolocation.watchPosition(
    (pos) => onGeoSuccess(pos),
    (err) => onGeoError(err),
    { enableHighAccuracy: true, maximumAge: 5000, timeout: 15000 }
  );
}

function onGeoSuccess(pos) {
  const { latitude, longitude, accuracy } = pos.coords;
  const now = new Date().toLocaleTimeString('en-US', { hour12: false });

  // Update stats
  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setEl('geo-lat', latitude.toFixed(6) + '°');
  setEl('geo-lng', longitude.toFixed(6) + '°');
  setEl('geo-acc', accuracy.toFixed(0) + 'm');
  setEl('geo-time', now);
  updateGeoStatus('🟢 Live GPS — Tracking active');

  // Trail log
  geoTrail.unshift(`[${now}]  ${latitude.toFixed(5)}, ${longitude.toFixed(5)}  ±${accuracy.toFixed(0)}m`);
  if (geoTrail.length > GEO_TRAIL_MAX) geoTrail.pop();
  const trailEl = document.getElementById('geo-trail-list');
  if (trailEl) {
    trailEl.innerHTML = geoTrail.map(t => `<div>${t}</div>`).join('');
  }

  // Drop a marker on the threat map if leaflet is ready
  if (leafletMap) {
    const existingMarker = window._geoSelfMarker;
    if (existingMarker) leafletMap.removeLayer(existingMarker);
    const marker = L.circleMarker([latitude, longitude], {
      radius: 9,
      fillColor: '#6366f1',
      color: '#a5b4fc',
      weight: 2,
      opacity: 1,
      fillOpacity: 0.85,
    }).bindPopup(`<div><strong>📍 Your Location (GPS)</strong><br>${latitude.toFixed(5)}, ${longitude.toFixed(5)}</div>`);
    marker.addTo(leafletMap);
    window._geoSelfMarker = marker;
  }
}

function onGeoError(err) {
  const messages = {
    1: 'Permission denied — Please allow location access',
    2: 'Position unavailable — Check device GPS',
    3: 'Timeout — GPS fix took too long',
  };
  updateGeoStatus('⚠️ ' + (messages[err.code] || err.message));
}

function updateGeoStatus(msg) {
  const el = document.getElementById('geo-status');
  if (el) el.textContent = msg;
}
