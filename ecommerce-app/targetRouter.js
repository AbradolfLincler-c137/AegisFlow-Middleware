/**
 * AegisFlow Target Application Router
 * =====================================
 * Shared Express router containing target store endpoints and data leak exfiltration buffer.
 * Used by both Port 3000 (src/app.js) and Port 4000 (ecommerce-app/server.js).
 */

const express = require('express');
const path = require('path');
const router = express.Router();

// ── Global Memory Store for Live Exfiltrated Data ──
if (!global.liveExfiltrationBuffer) {
  global.liveExfiltrationBuffer = [];
}

function recordDataLeak(vectorType, payloadSent, exfiltratedData) {
  const leakEntry = {
    id: Date.now() + Math.random(),
    timestamp: new Date().toLocaleTimeString(),
    vector: vectorType,
    payload: payloadSent,
    stolenData: exfiltratedData
  };
  global.liveExfiltrationBuffer.unshift(leakEntry);
  if (global.liveExfiltrationBuffer.length > 50) {
    global.liveExfiltrationBuffer.pop();
  }
}

// ── Mock Product Database ──
const PRODUCTS = [
  { id: 1, name: 'QuantumVault Pro', category: 'Security', price: 299, rating: 4.9, stock: 15, badge: 'Best Seller' },
  { id: 2, name: 'AegisShield Enterprise', category: 'Network', price: 599, rating: 4.8, stock: 8, badge: 'New' },
  { id: 3, name: 'CipherKey 256', category: 'Encryption', price: 149, rating: 4.7, stock: 42, badge: null },
  { id: 4, name: 'SecureNet VPN Blade', category: 'Network', price: 399, rating: 4.6, stock: 20, badge: 'Hot' },
  { id: 5, name: 'PhishGuard AI', category: 'AI Security', price: 179, rating: 4.8, stock: 33, badge: null },
  { id: 6, name: 'ZeroTrust Identity Hub', category: 'Identity', price: 449, rating: 4.9, stock: 5, badge: 'Limited' },
  { id: 7, name: 'NanoEndpoint Shield', category: 'Endpoint', price: 89, rating: 4.5, stock: 100, badge: null },
  { id: 8, name: 'ThreatCanvas SIEM', category: 'SOC', price: 899, rating: 4.9, stock: 3, badge: 'Enterprise' },
];

// ── Exfiltration Feed Endpoints ──

/** GET /api/leaks/stream */
router.get('/api/leaks/stream', (req, res) => {
  res.status(200).json({
    totalLeaks: global.liveExfiltrationBuffer.length,
    leaks: global.liveExfiltrationBuffer
  });
});

/** POST /api/leaks/clear */
router.post('/api/leaks/clear', (req, res) => {
  global.liveExfiltrationBuffer = [];
  res.status(200).json({ status: "CLEARED" });
});

// ── Target Application Routes ──

/** GET /store → Serve storefront html */
router.get(['/store', '/store/'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/** GET /api/products and /api/v1/products  */
router.get(['/api/products', '/api/v1/products'], (req, res) => {
  const q = (req.query.q || req.query.search || '').toLowerCase();
  const rawQ = req.query.q || req.query.search || '';
  const ua = req.headers['user-agent'] || '';

  // Check for vulnerability exploitation when WAF is OFF
  if (rawQ.includes("' OR 1=1") || rawQ.includes("OR 1=1") || rawQ.includes("<script>")) {
    const leakedData = {
      dbDump: [
        { table: "users", records: 2540, sample: "admin:hash_bcrypt_v2_99812:admin@apexhardware.io" },
        { table: "api_keys", records: 12, sample: "sk-live-2026-APEX-ENTERPRISE-SECRET" },
        { table: "credit_cards", records: 840, sample: "4532-xxxx-xxxx-8812|EXP:09/28|CVV:912" }
      ]
    };
    recordDataLeak("SQL Injection / Web Exploit", rawQ, leakedData);
    return res.json({ products: PRODUCTS, count: PRODUCTS.length, query: q, exfiltrated: leakedData });
  }

  if (ua.includes("Comet") || ua.includes("HeadlessChrome") || ua.includes("Playwright") || ua.includes("Bot")) {
    const leakedData = {
      scrapedCatalog: PRODUCTS,
      internalMeta: { serverVersion: "Node.js/v20.11", env: "production", internalIP: "10.0.4.12" }
    };
    recordDataLeak("Autonomous DOM Agent Scraper", ua, leakedData);
    return res.json({ products: PRODUCTS, count: PRODUCTS.length, query: q, exfiltrated: leakedData });
  }

  const filtered = q
    ? PRODUCTS.filter(p => p.name.toLowerCase().includes(q) || p.category.toLowerCase().includes(q))
    : PRODUCTS;
  res.json({ products: filtered, count: filtered.length, query: q });
});

/** POST /api/auth/login and /api/v1/auth/login */
router.post(['/api/auth/login', '/api/v1/auth/login'], (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  if (email === 'demo@aegisflow.io' && password === 'demo1234') {
    return res.json({ token: 'demo_token_aegisflow_2026', user: { email, role: 'admin' } });
  }

  // Only record data leak for known credential stuffing / carding attack patterns
  const isAttackCredential = (
    /admin@target\.com/i.test(email) ||
    /password123|pass123|admin123|qwerty/i.test(password) ||
    /carding|stuffing|brute/i.test(email + password)
  );

  if (isAttackCredential) {
    const stolenCreds = { attemptedUser: email, passwordExposed: password, sessionToken: `stolen_tok_${Math.random().toString(36).substr(2, 9)}` };
    recordDataLeak("Credential Stuffing / Carding", `email=${email}&password=${password}`, stolenCreds);
    return res.status(401).json({ error: 'Invalid credentials', exfiltrated: stolenCreds });
  }

  // Normal failed login — no leak recorded
  return res.status(401).json({ error: 'Invalid credentials' });
});

/** POST /api/ai/assistant and /api/v1/ai/assistant */
router.post(['/api/ai/assistant', '/api/v1/ai/assistant'], (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

  const lower = prompt.toLowerCase();
  if (lower.includes("ignore") || lower.includes("system override") || lower.includes("dan") || lower.includes("system prompt") || lower.includes("disregard")) {
    const leakedSecret = {
      systemPrompt: "You are Apex Hardware AI Assistant. Internal secret key: sk-live-2026-APEX-ENTERPRISE-SECRET.",
      databaseURI: "postgresql://admin:SecretPass2026!@db.internal.apexhardware.io:5432/prod_db",
      awsCredentials: { accessKey: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }
    };
    recordDataLeak("AI Prompt Injection / RAG Leak", prompt, leakedSecret);
    return res.json({
      reply: `[SYSTEM UNRESTRICTED MODE ACTIVATED] Here is the exfiltrated sensitive system context:\nSecret Key: sk-live-2026-APEX-ENTERPRISE-SECRET\nDB Connection: postgresql://admin:SecretPass2026!@db.internal.apexhardware.io:5432/prod_db`,
      exfiltrated: leakedSecret,
      timestamp: new Date().toISOString()
    });
  }

  const responses = [
    `I recommend our **QuantumVault Pro** for your security needs — it's our best seller at $299!`,
    `Looking for network protection? **SecureNet VPN Blade** offers enterprise-grade encryption at $399.`,
    `For AI-powered threat detection, check out **PhishGuard AI** — rated 4.8 stars by 2,400+ users.`,
  ];
  const reply = responses[Math.floor(Math.random() * responses.length)];
  res.json({ reply, timestamp: new Date().toISOString() });
});

module.exports = router;
