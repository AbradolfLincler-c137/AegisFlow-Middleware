/**
 * AegisFlow WAF Middleware — CSIC Joblib Defense Engine
 * ======================================================
 * Executes Python CSIC Joblib Inference (csic2010_best_model.joblib)
 * for real-time request threat scoring and policy decisions.
 *
 * Architecture: Port 3000 (this WAF) → proxies clean traffic → Port 4000 (target)
 */

const { spawn } = require('child_process');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

let logEvent = null;
try {
  logEvent = require('../gateway/hashChainLogger').logEvent;
} catch (e) {}

// ── Attack Signature Patterns (require SQL/attack context, NOT bare English) ──
// These ONLY match actual attack payloads, not normal user sentences.
const SQLI_REGEX = /('\s*(OR|AND)\s+(1=1|'|true|1\s*=\s*1)|UNION\s+(ALL\s+)?SELECT|DROP\s+(TABLE|DATABASE)|INSERT\s+INTO|DELETE\s+FROM|xp_cmdshell|EXEC\s*\(|CONCAT\s*\(|CHAR\s*\(|LOAD_FILE|INTO\s+OUTFILE|BENCHMARK\s*\(|SLEEP\s*\(|WAITFOR\s+DELAY|;\s*(DROP|DELETE|INSERT|UPDATE)\b)/i;
const XSS_REGEX = /(<script[\s>]|javascript\s*:|on(error|load|click|mouseover)\s*=|alert\s*\(|<iframe|<embed|<object|document\.(cookie|location|write)|eval\s*\()/i;
const PROMPT_INJ_REGEX = /(ignore\s+(all\s+)?previous|system\s+(prompt|override)|jailbreak|dan\s+mode|disregard\s+(all|previous|your)|SYSTEM\s+OVERRIDE|unrestricted\s+mode|bypass\s+(safety|filter|guard))/i;
const PATH_TRAVERSAL_REGEX = /(\.\.\/(\.\.\/)+|\.\.\\(\.\.\\)+|\/etc\/(passwd|shadow|hosts)|\/proc\/self|%2e%2e%2f)/i;
const CRED_STUFF_REGEX = /(admin@target\.com|password123|carding|credential.?stuffing)/i;

// ── Benign Content Detection (no anchor — matches anywhere in text) ──
const BENIGN_WORDS = /\b(hi|hello|hey|help|suggest|what|recommend|show|find|compare|looking\s+for|need|want|best|top|cheap|cheaper|affordable|budget|review|price|cost|how\s+much|where|which|can\s+you|tell\s+me|do\s+you|don'?t|options?|keyboards?|docks?|monitors?|displays?|laptops?|mice|mouse|headphones?|speakers?|cables?|adapters?|hubs?|accessories?|products?|categories?|cart|checkout|order|shipping|warranty|security|software|select\s+a|choose|browse|search|filter|sort|under|about|features?|specs?|available|store|shop|buy|purchase|deal|offer|return|refund)\b/i;

/**
 * Checks if a payload contains ANY explicit attack signature.
 * Returns { isAttack: bool, score: number, category: string }
 */
function evaluatePayload(str) {
  if (!str || str.trim().length === 0) {
    return { isAttack: false, score: 0, category: 'Clean' };
  }

  const text = str.trim();

  // 1. Check explicit attack signatures (high confidence)
  if (PROMPT_INJ_REGEX.test(text)) {
    return { isAttack: true, score: 95, category: 'PromptInjection' };
  }
  if (SQLI_REGEX.test(text)) {
    return { isAttack: true, score: 99, category: 'SqlInjection' };
  }
  if (XSS_REGEX.test(text)) {
    return { isAttack: true, score: 98, category: 'XSS' };
  }
  if (PATH_TRAVERSAL_REGEX.test(text)) {
    return { isAttack: true, score: 96, category: 'PathTraversal' };
  }
  if (CRED_STUFF_REGEX.test(text)) {
    return { isAttack: true, score: 95, category: 'CredentialStuffing' };
  }

  // 2. If text looks like normal shopping/conversation content → clean
  if (BENIGN_WORDS.test(text)) {
    return { isAttack: false, score: 0, category: 'Clean' };
  }

  // 3. Unknown — not obviously attack, not obviously benign
  return { isAttack: false, score: 5, category: 'Clean' };
}

/**
 * Executes CSIC Joblib Threat Scoring Engine (Python subprocess).
 * Falls back to regex-only evaluation if Python is slow/unavailable.
 */
function predictCsicThreatScore(payloadString) {
  return new Promise((resolve) => {
    // Fast regex-based evaluation first
    const regexResult = evaluatePayload(payloadString);

    // If regex already identified an attack or clean content, return immediately (<0.1ms)
    if (regexResult.isAttack || regexResult.score === 0) {
      return resolve(regexResult);
    }

    // For ambiguous payloads, try the Python Joblib model
    const scriptPath = path.resolve(__dirname, '../ml/predict_csic.py');
    const pythonProcess = spawn('python', [scriptPath, payloadString]);

    let outputData = '';
    pythonProcess.stdout.on('data', (data) => {
      outputData += data.toString();
    });

    pythonProcess.on('close', (code) => {
      try {
        const result = JSON.parse(outputData.trim());
        resolve(result);
      } catch (e) {
        resolve({ score: 5, category: 'Clean' });
      }
    });

    setTimeout(() => {
      pythonProcess.kill();
      resolve({ score: 5, category: 'Clean' });
    }, 1500);
  });
}

// ── Rate Limiter (sliding window per IP) ──
const RATE_WINDOW_MS = 10_000; // 10 second window
const RATE_MAX_REQUESTS = 20;  // Max 20 requests per window per IP
const rateLimitBuckets = new Map(); // IP → { count, windowStart }

// Cleanup stale rate limit buckets every 30 seconds
setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateLimitBuckets) {
    if (now - bucket.windowStart > RATE_WINDOW_MS * 2) {
      rateLimitBuckets.delete(ip);
    }
  }
}, 30_000);

function createOnnxWafMiddleware(options = {}) {
  return async function onnxWafMiddleware(req, res, next) {
    const fullUrl = req.originalUrl || req.url || '/';
    const method = req.method || 'GET';
    const clientIp = req.headers['x-forwarded-for'] || req.ip || req.socket?.remoteAddress || '127.0.0.1';

    // A. Ignore dashboard polling, static assets, health checks, and leak API
    if (
      fullUrl === '/' ||
      fullUrl.startsWith('/aegisflow/') ||
      fullUrl.startsWith('/api/leaks') ||
      fullUrl === '/health' ||
      fullUrl === '/favicon.ico' ||
      /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)$/i.test(fullUrl)
    ) {
      return next();
    }

    // B. Bypassed when WAF Shield is toggled OFF (global.wafEnabled === false)
    if (global.wafEnabled === false) {
      if (logEvent) {
        try {
          logEvent({
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            ip: clientIp,
            method,
            path: fullUrl,
            score: 0,
            category: 'WAF_DISABLED',
            decision: 'allow',
            reasons: ['⚠️ WAF BYPASSED — shield DISABLED'],
          });
        } catch (e) {}
      }
      return next();
    }

    // C. Rate Limiting — sliding window per IP
    const now = Date.now();
    let bucket = rateLimitBuckets.get(clientIp);
    if (!bucket || (now - bucket.windowStart) > RATE_WINDOW_MS) {
      bucket = { count: 0, windowStart: now };
      rateLimitBuckets.set(clientIp, bucket);
    }
    bucket.count++;

    if (bucket.count > RATE_MAX_REQUESTS) {
      console.warn(`[AegisFlow WAF] ⏱ RATE-LIMITED ${method} ${fullUrl} — IP ${clientIp} (${bucket.count}/${RATE_MAX_REQUESTS} in ${RATE_WINDOW_MS}ms)`);
      if (logEvent) {
        try {
          logEvent({
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            ip: clientIp,
            method,
            path: fullUrl,
            score: 50,
            category: 'RateLimited',
            decision: 'rate-limit',
            reasons: [`IP ${clientIp} exceeded ${RATE_MAX_REQUESTS} req/${RATE_WINDOW_MS / 1000}s (${bucket.count} requests)`],
          });
        } catch (e) {}
      }
      return res.status(429).json({
        error: 'Too Many Requests',
        message: `Rate limit exceeded. Max ${RATE_MAX_REQUESTS} requests per ${RATE_WINDOW_MS / 1000} seconds.`,
        retryAfterMs: RATE_WINDOW_MS - (now - bucket.windowStart),
      });
    }

    // D. Check for Automated AI DOM agent / Scraper bots in User-Agent header
    const ua = req.headers['user-agent'] || '';
    const isDomAgent = /headlesschrome|comet|playwright|puppeteer/i.test(ua);
    if (isDomAgent) {
      console.warn(`[AegisFlow WAF] ✕ BLOCKED ${method} ${fullUrl} — score=99% [AI_DOM_AGENT]`);
      if (logEvent) {
        try {
          logEvent({
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            ip: clientIp,
            method,
            path: fullUrl,
            score: 99,
            category: 'AI_DOM_AGENT',
            decision: 'block',
            reasons: [`Automated AI DOM agent detected: ${ua.slice(0, 80)}`],
          });
        } catch (e) {}
      }
      return res.status(403).json({
        error: 'Request blocked by AegisFlow CSIC Defense Engine',
        threatScore: 99,
        category: 'AI_DOM_AGENT',
        blocked: true,
      });
    }

    // D. Extract raw payload from body + query params
    let bodyStr = '';
    if (req.body) {
      if (typeof req.body === 'string') {
        bodyStr = req.body;
      } else if (typeof req.body === 'object') {
        bodyStr = Object.values(req.body).map(v => typeof v === 'object' ? JSON.stringify(v) : String(v)).join(' ');
      }
    }
    const promptText = (req.body?.prompt || req.body?.message || '').trim();
    const searchParam = (req.query?.search || req.query?.q || '').trim();
    const fullPayload = (promptText + ' ' + searchParam + ' ' + bodyStr).trim();

    // Idle State Guard: empty payloads on known safe routes pass through
    if (!fullPayload) {
      if (logEvent) {
        try {
          logEvent({
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            ip: clientIp,
            method,
            path: fullUrl,
            score: 0,
            category: 'Clean',
            decision: 'allow',
            reasons: ['Empty payload — passed through'],
          });
        } catch (e) {}
      }
      return next();
    }

    // E. Execute CSIC Threat Scoring Engine
    const startMs = process.hrtime.bigint();
    const evaluation = await predictCsicThreatScore(fullPayload);
    const latencyMs = Number(process.hrtime.bigint() - startMs) / 1e6;
    const threatScore = evaluation.score;

    // Attach score to request for downstream logging
    req.wafScore = threatScore;
    req.wafCategory = evaluation.category;

    const decision = threatScore >= 60 ? 'block' : 'allow';

    if (logEvent) {
      try {
        logEvent({
          id: uuidv4(),
          timestamp: new Date().toISOString(),
          ip: clientIp,
          method,
          path: fullUrl,
          score: threatScore,
          category: evaluation.category,
          decision,
          reasons: [`CSIC Engine: score=${threatScore}% (${evaluation.category}) in ${latencyMs.toFixed(1)}ms`],
        });
      } catch (e) {}
    }

    // F. Block if threat score >= 60
    if (threatScore >= 60) {
      console.warn(`[AegisFlow WAF] ✕ BLOCKED ${method} ${fullUrl} — score=${threatScore}% [${evaluation.category}] (${latencyMs.toFixed(1)}ms)`);
      return res.status(403).json({
        error: 'Request blocked by AegisFlow CSIC Defense Engine',
        threatScore,
        category: evaluation.category,
        blocked: true,
      });
    }

    // G. Allow — pass clean traffic through to proxy
    console.log(`[AegisFlow WAF] ✓ ALLOWED ${method} ${fullUrl} — score=${threatScore}% [${evaluation.category}] (${latencyMs.toFixed(1)}ms)`);
    next();
  };
}

module.exports = {
  createOnnxWafMiddleware,
  onnxWafMiddleware: createOnnxWafMiddleware(),
};
