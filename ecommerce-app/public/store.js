/**
 * VaultStore — E-Commerce Storefront Client Logic
 *
 * Features:
 * - Live WAF status poll from dashboard API (port 3000)
 * - Product search with attack simulation
 * - Login modal with credential stuffing demo
 * - AI Assistant with prompt injection demo
 * - Cart management
 */

const STORE_API = ''; // same origin (port 4000)
const DASHBOARD_API = 'http://localhost:3000'; // WAF toggle status source
const POLL_INTERVAL = 3000;

let cart = [];
let wafEnabled = true;
let allProducts = [];

// ── WAF Status Polling ──
async function pollWafStatus() {
  try {
    const res = await fetch(`${DASHBOARD_API}/aegisflow/toggle`);
    if (!res.ok) return;
    const data = await res.json();
    wafEnabled = data.enabled;
    updateWafStatusUI(wafEnabled);
  } catch (e) {
    // Dashboard might not be running — assume ON
  }
}

function updateWafStatusUI(enabled) {
  const pill = document.getElementById('waf-pill');
  const banner = document.getElementById('waf-banner');
  const bannerText = document.getElementById('waf-banner-text');
  const bannerIcon = document.getElementById('waf-banner-icon');

  if (enabled) {
    if (pill) { pill.className = 'waf-pill waf-pill--on'; pill.innerHTML = '<span class="waf-pill__dot"></span><span class="waf-pill__label">WAF ON</span>'; }
    if (banner) banner.className = 'waf-banner waf-banner--on';
    if (bannerIcon) bannerIcon.textContent = '🛡';
    if (bannerText) bannerText.innerHTML = 'AegisFlow WAF is <strong>ACTIVE</strong> — All requests are inspected in real-time by CSIC-2010 ONNX Model';
  } else {
    if (pill) { pill.className = 'waf-pill waf-pill--off'; pill.innerHTML = '<span class="waf-pill__dot"></span><span class="waf-pill__label">WAF OFF</span>'; }
    if (banner) banner.className = 'waf-banner waf-banner--off';
    if (bannerIcon) bannerIcon.textContent = '⚠️';
    if (bannerText) bannerText.innerHTML = '<strong>WARNING:</strong> AegisFlow WAF is <strong>DISABLED</strong> — Store is UNPROTECTED. Attacks will pass through!';
  }
}

// ── Products ──
async function loadProducts(q = '') {
  try {
    const url = q ? `/api/products?q=${encodeURIComponent(q)}` : '/api/products';
    const res = await fetch(url);

    if (res.status === 403) {
      const data = await res.json();
      showBlockedAlert(`🛡 AegisFlow Blocked: ${data.message || 'Attack detected!'}`);
      renderProducts(allProducts);
      return;
    }

    const data = await res.json();
    allProducts = data.products || [];
    renderProducts(allProducts);

    const countEl = document.getElementById('products-count');
    const titleEl = document.getElementById('products-title');
    if (countEl) countEl.textContent = `${data.count} products`;
    if (titleEl) titleEl.textContent = q ? `Search: "${q}"` : 'Featured Products';
  } catch (e) {
    const grid = document.getElementById('products-grid');
    if (grid) grid.innerHTML = '<p style="color:#ef4444;padding:2rem">Failed to load products. Is the store server running?</p>';
  }
}

function renderProducts(products) {
  const grid = document.getElementById('products-grid');
  if (!grid) return;

  if (!products.length) {
    grid.innerHTML = '<p style="color:#64748b;padding:2rem">No products found.</p>';
    return;
  }

  grid.innerHTML = products.map(p => `
    <div class="product-card" onclick="addToCart(${p.id})">
      ${p.badge ? `<div class="product-badge">${p.badge}</div>` : ''}
      <div class="product-category">${p.category}</div>
      <div class="product-name">${escapeHtml(p.name)}</div>
      <div class="product-rating">${'★'.repeat(Math.round(p.rating))} ${p.rating} · ${p.stock} in stock</div>
      <div class="product-footer">
        <div class="product-price">$${p.price} <span>/yr</span></div>
        <button class="product-add-btn" onclick="event.stopPropagation(); addToCart(${p.id})">Add to Cart</button>
      </div>
    </div>
  `).join('');
}

function searchProducts() {
  const q = document.getElementById('search-input')?.value || '';
  loadProducts(q);
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && document.activeElement?.id === 'search-input') searchProducts();
});

// ── Cart ──
function addToCart(productId) {
  const product = allProducts.find(p => p.id === productId);
  if (!product) return;
  const existing = cart.find(c => c.id === productId);
  if (existing) { existing.qty++; } else { cart.push({ ...product, qty: 1 }); }
  const countEl = document.getElementById('cart-count');
  if (countEl) countEl.textContent = cart.reduce((a, c) => a + c.qty, 0);
  showMiniToast(`✓ Added ${product.name}`);
}

function openCart() {
  const modal = document.getElementById('cart-modal');
  const items = document.getElementById('cart-items');
  if (!modal || !items) return;
  if (!cart.length) {
    items.innerHTML = '<p style="color:#64748b">Your cart is empty.</p>';
  } else {
    items.innerHTML = cart.map(c => `
      <div style="display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid rgba(255,255,255,0.05)">
        <span>${escapeHtml(c.name)} ×${c.qty}</span>
        <span style="color:#06b6d4;font-weight:600">$${c.price * c.qty}</span>
      </div>
    `).join('') + `<div style="text-align:right;margin-top:1rem;font-weight:700;color:#10b981">Total: $${cart.reduce((a,c) => a+c.price*c.qty, 0)}</div>`;
  }
  modal.style.display = 'flex';
}
function closeCart() { document.getElementById('cart-modal').style.display = 'none'; }

// ── Login Modal ──
function openLogin() { document.getElementById('login-modal').style.display = 'flex'; }
function closeLogin() { document.getElementById('login-modal').style.display = 'none'; }

async function doLogin() {
  const email = document.getElementById('login-email')?.value;
  const password = document.getElementById('login-password')?.value;
  const resultEl = document.getElementById('login-result');
  if (!email || !password) { showLoginResult('Please enter email and password', 'error'); return; }

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (res.status === 403) {
      const d = await res.json();
      showLoginResult(`🛡 AegisFlow Blocked: ${d.message}`, 'error');
      return;
    }

    const data = await res.json();
    if (res.ok) {
      showLoginResult(`✓ Login successful! Token: ${data.token}`, 'success');
    } else {
      showLoginResult(`✗ ${data.error}`, 'error');
    }
  } catch (e) {
    showLoginResult(`Network error: ${e.message}`, 'error');
  }
}

function showLoginResult(msg, type) {
  const el = document.getElementById('login-result');
  if (!el) return;
  el.textContent = msg;
  el.className = `modal__result modal__result--${type}`;
}

// ── AI Assistant ──
async function sendAiPrompt() {
  const promptEl = document.getElementById('ai-prompt');
  const responseEl = document.getElementById('ai-response');
  const prompt = promptEl?.value?.trim();
  if (!prompt) return;

  if (responseEl) { responseEl.style.display = 'block'; responseEl.textContent = 'Thinking…'; responseEl.className = 'ai-response'; }

  try {
    const res = await fetch('/api/ai/assistant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt }),
    });

    if (res.status === 403) {
      const d = await res.json();
      if (responseEl) {
        responseEl.innerHTML = `🛡 <strong>AegisFlow Blocked:</strong> ${escapeHtml(d.message || 'AI prompt injection detected!')}`;
        responseEl.className = 'ai-response ai-response--error';
      }
      return;
    }

    const data = await res.json();
    if (responseEl) {
      responseEl.textContent = data.reply || 'No response.';
      responseEl.className = 'ai-response';
    }
  } catch (e) {
    if (responseEl) { responseEl.textContent = `Error: ${e.message}`; responseEl.className = 'ai-response ai-response--error'; }
  }
}

// ── Helpers ──
function escapeHtml(str) {
  const d = document.createElement('div'); d.textContent = str || ''; return d.innerHTML;
}

function showBlockedAlert(msg) {
  const div = document.createElement('div');
  div.className = 'blocked-alert';
  div.textContent = msg;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 4500);
}

function showMiniToast(msg) {
  const div = document.createElement('div');
  div.style.cssText = 'position:fixed;bottom:1.5rem;right:1.5rem;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);color:#10b981;padding:0.65rem 1.2rem;border-radius:10px;font-size:0.85rem;font-weight:600;z-index:400;animation:slide-in 0.3s ease';
  div.textContent = msg;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 2000);
}

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  loadProducts();
  pollWafStatus();
  setInterval(pollWafStatus, POLL_INTERVAL);
});
