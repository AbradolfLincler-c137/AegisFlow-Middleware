/**
 * AegisFlow Dashboard — API Routes
 * 
 * Serves log/stats JSON from Person A's hashChainLogger.
 * Mounted under /aegisflow/ prefix in the main app.
 */

const express = require('express');
const path = require('path');
const { getRecentLogs, getStats, verifyChain, clearLogs } = require('../gateway/hashChainLogger');
const { isWafEnabled, setWafEnabled } = require('../gateway/wafState');

const router = express.Router();

// Explicit index.html route handlers for seamless browser navigation
router.get('/', (req, res) => {
  res.redirect('/aegisflow/dashboard');
});

router.get(['/aegisflow/dashboard', '/aegisflow/dashboard/'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve the dashboard static files (JS, CSS, images)
router.use('/aegisflow/dashboard', express.static(path.join(__dirname, 'public')));

/**
 * GET /aegisflow/logs?limit=50
 * Returns recent log entries, newest first.
 */
router.get('/aegisflow/logs', (req, res) => {
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 50));
  const logs = getRecentLogs(limit);
  res.json({ logs, count: logs.length });
});

/**
 * GET /aegisflow/stats
 * Returns aggregate statistics.
 */
router.get('/aegisflow/stats', (req, res) => {
  const stats = getStats();
  res.json(stats);
});

/**
 * GET /aegisflow/verify
 * Verifies the hash-chain integrity. Returns { intact: true/false, failedAtId?: string }.
 */
router.get('/aegisflow/verify', (req, res) => {
  const result = verifyChain();
  res.json({ ...result, verifiedAt: new Date().toISOString() });
});

/**
 * POST /aegisflow/verify/reset
 * Resets the hash chain logic buffer.
 */
router.post('/aegisflow/verify/reset', (req, res) => {
  clearLogs();
  res.json({ success: true, message: 'Hash chain reset successfully.' });
});

/**
 * GET /aegisflow/toggle
 * Returns current WAF protection state.
 */
router.get('/aegisflow/toggle', (req, res) => {
  res.json({ enabled: isWafEnabled() });
});

/**
 * POST /aegisflow/toggle
 * Body: { "enabled": true | false }
 * Sets WAF protection state.
 */
router.post('/aegisflow/toggle', (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'Body must be { "enabled": true | false }' });
  }
  const current = setWafEnabled(enabled);
  res.json({ enabled: current, message: `WAF protection ${current ? 'ENABLED' : 'DISABLED'}` });
});

const axios = require('axios');

/**
 * GET /aegisflow/leaks
 * Fetches current live exfiltrated data from VaultStore (port 4000).
 */
router.get('/aegisflow/leaks', async (req, res) => {
  try {
    const response = await axios.get('http://127.0.0.1:4000/api/leaks/stream', { timeout: 2000 });
    return res.json(response.data);
  } catch (err) {
    return res.json({ totalLeaks: 0, leaks: [], error: 'VaultStore offline' });
  }
});

/**
 * POST /aegisflow/leaks/clear
 * Clears exfiltration buffer on VaultStore (port 4000).
 */
router.post('/aegisflow/leaks/clear', async (req, res) => {
  try {
    const response = await axios.post('http://127.0.0.1:4000/api/leaks/clear', {}, { timeout: 2000 });
    return res.json(response.data);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to clear leaks buffer' });
  }
});

module.exports = router;
