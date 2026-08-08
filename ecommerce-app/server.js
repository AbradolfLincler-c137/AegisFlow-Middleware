/**
 * AegisFlow E-Commerce Target App — Server
 * ==========================================
 * Standalone Express app on Port 4000.
 * This is the RAW TARGET — NO WAF protection here.
 * The WAF gateway on Port 3000 proxies clean traffic to this server.
 *
 * When WAF is ON:  attacks are blocked at Port 3000 (never reach here)
 * When WAF is OFF: attacks pass through to Port 4000 (data leaks occur)
 */

const express = require('express');
const path = require('path');
const cors = require('cors');

const targetRouter = require('./targetRouter');

const app = express();
const PORT = 4000;

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── NO WAF HERE — this is the unprotected target application ──

// ── Static storefront files ──
app.use(express.static(path.join(__dirname, 'public')));

// ── Target Application & Exfiltration Routes ──
app.use(targetRouter);

/** Health check */
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', app: 'AegisFlow E-Commerce Target (UNPROTECTED)', port: PORT });
});

app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════╗');
  console.log('  ║       🛒 Target Store — Port 4000 (NO WAF)          ║');
  console.log('  ╠══════════════════════════════════════════════════════╣');
  console.log(`  ║  Store:       http://localhost:${PORT}                    ║`);
  console.log(`  ║  Products API: http://localhost:${PORT}/api/products      ║`);
  console.log(`  ║  Leaks Feed:  http://localhost:${PORT}/api/leaks/stream   ║`);
  console.log('  ║  ⚠️  NO WAF — protected via localhost:3000 gateway   ║');
  console.log('  ╚══════════════════════════════════════════════════════╝');
  console.log('');
});

module.exports = app;

