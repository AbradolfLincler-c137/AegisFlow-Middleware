/**
 * AegisFlow — WAF Gateway (Port 3000)
 * 
 * Reverse proxy architecture:
 *   1. Receives ALL incoming requests
 *   2. Runs WAF middleware (CSIC threat scoring)
 *   3. BLOCKED requests → 403 (never reach target)
 *   4. CLEAN requests → proxied to Port 4000 (target store)
 *   5. Dashboard UI served locally
 * 
 * Target store runs on Port 4000 with NO WAF — this gateway is the shield.
 */

const express = require('express');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

// --- App Setup ---
const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_PORT = process.env.TARGET_PORT || 4000;
const TARGET_URL = `http://127.0.0.1:${TARGET_PORT}`;

const cors = require('cors');
const { createOnnxWafMiddleware } = require('./middleware/onnxWaf');

// Body parsers & CORS
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Mount Dashboard Routes (served locally, NOT proxied) ---
const dashboardRoutes = require('./dashboard/dashboard.routes');
app.use(dashboardRoutes);

// --- Health Check (local) ---
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    components: {
      gateway: 'active',
      waf: 'active',
      dashboard: 'active',
      target: TARGET_URL,
    },
  });
});

// --- Mount AegisFlow WAF Middleware ---
// This runs BEFORE the proxy. If it blocks (403), request never reaches Port 4000.
const waf = createOnnxWafMiddleware({ threshold: 0.7 });
app.use(waf);

// --- Proxy clean traffic to Port 4000 (target store) ---
// Any request that passes the WAF is forwarded to the target application.
const proxy = createProxyMiddleware({
  target: TARGET_URL,
  changeOrigin: true,
  // Don't parse body again — we already parsed it for WAF inspection
  on: {
    proxyReq: (proxyReq, req) => {
      // Re-attach the body that express.json() already consumed
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
    },
    error: (err, req, res) => {
      console.error(`[AegisFlow Gateway] Proxy error: ${err.message}`);
      if (res.headersSent) return;
      res.status(502).json({
        error: 'Bad Gateway',
        message: `Target store (Port ${TARGET_PORT}) is unreachable. Is it running?`,
      });
    },
  },
});

app.use(proxy);

// --- Start Server ---
app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════╗');
  console.log('  ║         🛡️  AegisFlow WAF Gateway — ACTIVE          ║');
  console.log('  ╠══════════════════════════════════════════════════════╣');
  console.log(`  ║  Gateway:     http://localhost:${PORT}                    ║`);
  console.log(`  ║  Target:      http://localhost:${TARGET_PORT} (proxied)            ║`);
  console.log(`  ║  Dashboard:   http://localhost:${PORT}/aegisflow/dashboard ║`);
  console.log('  ║  Health:      /health                              ║');
  console.log('  ╚══════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  WAF inspects all traffic → clean requests proxied to Port ${TARGET_PORT}`);
  console.log(`  Blocked requests get 403 and NEVER reach the target store.`);
  console.log('');
});

module.exports = app;

