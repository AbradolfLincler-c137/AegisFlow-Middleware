/**
 * AegisFlow WAF Toggle State
 * ===========================
 * Global in-memory WAF enable/disable flag.
 * Uses `global.wafEnabled` so it is accessible across
 * all modules in the same Node.js process without require() cycling.
 *
 * API:
 *   isWafEnabled()        → boolean
 *   setWafEnabled(bool)   → boolean (new state)
 */

// Initialize global flag (default: protection ON)
if (typeof global.wafEnabled === 'undefined') {
  global.wafEnabled = true;
}

function isWafEnabled() {
  return global.wafEnabled === true;
}

function setWafEnabled(value) {
  global.wafEnabled = Boolean(value);
  const state = global.wafEnabled ? '🟢 ENABLED' : '🔴 DISABLED';
  console.log(`[AegisFlow WAF] Protection ${state} — shield ${global.wafEnabled ? 'ACTIVE' : 'BYPASSED'}`);
  return global.wafEnabled;
}

module.exports = { isWafEnabled, setWafEnabled };
