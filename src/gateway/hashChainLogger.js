/**
 * AegisFlow — Hash-Chain Logger
 * 
 * Immutable audit log with SHA-256 hash chain.
 * Each entry links to the previous via hash, making tampering detectable.
 * 
 * Hash formula: sha256(previousHash + JSON.stringify(entryWithoutHash))
 * 
 * Exports (per shared contract):
 *   logEvent(entry)           — appends entry, computes hash chain link
 *   getRecentLogs(limit=50)   — returns array, newest first
 *   getStats()                — returns { total, byCategory, byDecision }
 *   verifyChain()             — walks chain, checks every hash link, returns bool
 */

const crypto = require('crypto');

const MAX_LOG_SIZE = 500;
const logs = [];

/**
 * Compute SHA-256 hash for chain linking.
 * Formula: sha256(previousHash + JSON.stringify(entryFieldsWithoutHash))
 * 
 * @param {Object} entry - The log entry (without hash fields)
 * @param {string|null} previousHash
 * @returns {string} Hex-encoded SHA-256 hash
 */
function computeHash(entry, previousHash) {
  const payload = (previousHash || '') + JSON.stringify({
    id: entry.id,
    timestamp: entry.timestamp,
    ip: entry.ip,
    method: entry.method,
    path: entry.path,
    score: entry.score,
    category: entry.category,
    decision: entry.decision,
    reasons: entry.reasons,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Append a log entry with hash-chain linking.
 * @param {Object} entry - Must have: id, timestamp, ip, method, path, score, category, decision, reasons
 */
function logEvent(entry) {
  const previousHash = logs.length > 0 ? logs[logs.length - 1].currentHash : null;
  const currentHash = computeHash(entry, previousHash);

  const fullEntry = {
    id: entry.id,
    timestamp: entry.timestamp,
    ip: entry.ip,
    method: entry.method,
    path: entry.path,
    score: entry.score,
    category: entry.category,
    decision: entry.decision,
    reasons: entry.reasons,
    previousHash,
    currentHash,
  };

  logs.push(fullEntry);

  // Evict oldest entries if over cap
  if (logs.length > MAX_LOG_SIZE) {
    logs.splice(0, logs.length - MAX_LOG_SIZE);
  }
}

/**
 * Return recent log entries, newest first.
 * @param {number} limit - Max entries to return (default 50)
 * @returns {Object[]}
 */
function getRecentLogs(limit = 50) {
  const start = Math.max(0, logs.length - limit);
  return logs.slice(start).reverse();
}

/**
 * Return aggregate statistics.
 * @returns {{ total: number, byCategory: Object<string, number>, byDecision: Object<string, number> }}
 */
function getStats() {
  const byCategory = {};
  const byDecision = {};

  for (const entry of logs) {
    byCategory[entry.category] = (byCategory[entry.category] || 0) + 1;
    byDecision[entry.decision] = (byDecision[entry.decision] || 0) + 1;
  }

  return {
    total: logs.length,
    byCategory,
    byDecision,
  };
}

/**
 * Walk the entire chain and verify every hash link.
 * Returns object with intact boolean, and failedAtId if tampering detected.
 * @returns {{ intact: boolean, failedAtId?: string }}
 */
function verifyChain() {
  if (logs.length === 0) return { intact: true };

  // Verify first entry
  const first = logs[0];
  if (first.previousHash !== null) return { intact: false, failedAtId: first.id };
  const expectedFirstHash = computeHash(first, null);
  if (first.currentHash !== expectedFirstHash) return { intact: false, failedAtId: first.id };

  // Walk the rest
  for (let i = 1; i < logs.length; i++) {
    const entry = logs[i];
    const prev = logs[i - 1];

    // Chain link check: entry.previousHash must match prev.currentHash
    if (entry.previousHash !== prev.currentHash) return { intact: false, failedAtId: entry.id };

    // Recompute and verify
    const expectedHash = computeHash(entry, entry.previousHash);
    if (entry.currentHash !== expectedHash) return { intact: false, failedAtId: entry.id };
  }

  return { intact: true };
}

function clearLogs() {
  logs.length = 0;
}

module.exports = {
  logEvent,
  getRecentLogs,
  getStats,
  verifyChain,
  clearLogs,
  // Exposed for tamper-testing demos (not part of public contract)
  _logs: logs,
};
