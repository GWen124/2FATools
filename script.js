// Base32 decode (RFC4648, ignore spaces and case, support padding)
function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = base32.replace(/\s+/g, "").toUpperCase().replace(/=+$/g, "");
  if (!clean) return new Uint8Array();
  let bits = 0, value = 0, index = 0;
  const out = [];
  for (const c of clean) {
    const v = alphabet.indexOf(c);
    if (v === -1) throw new Error("无效的 Base32 字符: " + c);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function parseInputToParams(input, defaults) {
  const d = Object.assign({ algorithm: 'SHA-1', period: 30, digits: 6, label: '', issuer: '' }, defaults || {});
  const t = input.trim();
  if (t.toLowerCase().startsWith('otpauth://')) {
    try {
      const url = new URL(t);
      const type = url.host; // totp
      if (type !== 'totp') throw new Error('仅支持 TOTP');
      const labelRaw = decodeURIComponent(url.pathname.replace(/^\//, ''));
      const labelParts = labelRaw.split(':');
      let label = labelRaw;
      if (labelParts.length > 1) label = labelParts.slice(1).join(':');
      const params = url.searchParams;
      const secret = params.get('secret') || '';
      const issuer = params.get('issuer') || (labelParts.length > 1 ? labelParts[0] : '');
      const algorithm = (params.get('algorithm') || d.algorithm).toUpperCase();
      const digits = parseInt(params.get('digits') || d.digits, 10);
      const period = parseInt(params.get('period') || d.period, 10);
      return { secret, algorithm, digits, period, label, issuer };
    } catch (e) {
      throw new Error('otpauth URI 解析失败: ' + e.message);
    }
  }
  // otherwise treat as raw base32 secret
  return { secret: t, algorithm: d.algorithm, digits: d.digits, period: d.period, label: d.label, issuer: d.issuer };
}

async function hmacDigest(algorithm, keyBytes, msgBytes) {
  const subtleAlg = { name: 'HMAC', hash: { name: algorithm } };
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, subtleAlg, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, msgBytes);
  return new Uint8Array(sig);
}

function intToBytesBE(num) {
  const b = new Uint8Array(8);
  const view = new DataView(b.buffer);
  view.setUint32(0, Math.floor(num / 0x100000000), false);
  view.setUint32(4, num >>> 0, false);
  return b;
}

async function generateTotp(secretBase32, options) {
  const { algorithm = 'SHA-1', digits = 6, period = 30, timestampMs = Date.now() } = options || {};
  const key = base32ToBytes(secretBase32);
  const counter = Math.floor(timestampMs / 1000 / period);
  const msg = intToBytesBE(counter);
  const mac = await hmacDigest(algorithm, key, msg);
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | ((mac[offset + 1] & 0xff) << 16) | ((mac[offset + 2] & 0xff) << 8) | (mac[offset + 3] & 0xff);
  const mod = 10 ** digits;
  const code = (bin % mod).toString().padStart(digits, '0');
  return { code };
}

function buildOtpauthURI({ secret, label = '', issuer = '', algorithm = 'SHA-1', digits = 6, period = 30 }) {
  const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
  if (!cleanSecret) throw new Error('缺少 secret');
  let issuerTrim = (issuer || '').trim();
  let account = (label || '').trim();
  // If issuer present but account empty, default account to avoid trailing colon
  if (issuerTrim && !account) account = 'Account';
  if (!issuerTrim && !account) {
    issuerTrim = '2FA';
    account = 'Account';
  }
  const encodedIssuer = encodeURIComponent(issuerTrim);
  const encodedAccount = encodeURIComponent(account);
  const labelForPath = issuerTrim ? `${encodedIssuer}:${encodedAccount}` : encodedAccount; // 保留未编码的冒号
  const url = new URL(`otpauth://totp/${labelForPath}`);
  url.searchParams.set('secret', cleanSecret);
  if (issuerTrim) url.searchParams.set('issuer', issuerTrim);
  url.searchParams.set('algorithm', algorithm.toUpperCase());
  url.searchParams.set('digits', String(digits));
  url.searchParams.set('period', String(period));
  return url.toString();
}

// UI logic
const els = {
  input: document.getElementById('input'),
  parseBtn: document.getElementById('parseBtn'),
  code: document.getElementById('code'),
  progressBar: document.getElementById('progressBar'),
  meta: document.getElementById('meta'),
  copyBtn: document.getElementById('copyBtn'),
  qrBtn: document.getElementById('qrBtn'),
  modalOverlay: document.getElementById('modalOverlay'),
  modalClose: document.getElementById('modalClose'),
  qrcodeModal: document.getElementById('qrcodeModal'),
  copyUriBtn: document.getElementById('copyUriBtn'),
  downloadQrBtn: document.getElementById('downloadQrBtn'),
};

let state = {
  secret: '', algorithm: 'SHA-1', digits: 6, period: 30, label: '', issuer: '',
};

function applyParams(params) {
  state = Object.assign({}, state, params);
}

// Disable right-click globally except on textarea (will re-enable via event delegation)
document.addEventListener('contextmenu', (e) => {
  const target = e.target;
  if (target && (target.closest && target.closest('textarea'))) return;
  e.preventDefault();
});

// Initialize remaining label immediately
els.meta.textContent = '剩余时间还剩:';
els.meta.classList.remove('show');

let timer = null;
async function tick() {
  const now = Math.floor(Date.now() / 1000);
  const elapsed = now % state.period;
  const remain = state.period - elapsed;
  if (!state.secret) {
    els.code.textContent = '------';
    els.progressBar.style.width = '0%';
    els.meta.textContent = '剩余时间还剩:';
    els.meta.classList.remove('show');
    return;
  }
  try {
    const { code } = await generateTotp(state.secret, state);
    els.code.textContent = code;
    els.progressBar.style.width = `${(elapsed / state.period) * 100}%`;
    els.meta.textContent = `剩余时间还剩: ${remain}s`;
    els.meta.classList.add('show');
  } catch (e) {
    els.code.textContent = '错误';
    els.meta.textContent = e.message || String(e);
    els.meta.classList.add('show');
  }
}

function startLoop() {
  if (timer) clearInterval(timer);
  tick();
  timer = setInterval(tick, 250);
}

function triggerParse() {
  try {
    const params = parseInputToParams(els.input.value, state);
    if (!params.secret) throw new Error('缺少 secret');
    applyParams(params);
    startLoop();
  } catch (e) {
    alert(e.message || String(e));
  }
}

els.parseBtn.addEventListener('click', triggerParse);
els.input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (e.isComposing) return;
    triggerParse();
  }
});

els.copyBtn.addEventListener('click', async () => {
  try {
    const value = (els.code.textContent || '').trim();
    if (!state.secret || !/^\d{6,10}$/.test(value)) {
      alert('暂无可复制的验证码');
      return;
    }
    await navigator.clipboard.writeText(value);
    els.copyBtn.textContent = '已复制';
    setTimeout(() => (els.copyBtn.textContent = '点击复制验证码'), 1000);
  } catch {}
});

function openModal() {
  els.modalOverlay.setAttribute('aria-hidden', 'false');
}
function closeModal() {
  els.modalOverlay.setAttribute('aria-hidden', 'true');
  els.qrcodeModal.innerHTML = '';
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src; s.async = true; s.onload = resolve; s.onerror = reject; document.head.appendChild(s);
  });
}

async function ensureQrLib() {
  if (window.QRCode) return;
  try {
    await loadScript('https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js');
  } catch (e) {
    throw new Error('二维码库未加载，且 CDN 回退加载失败。请检查网络或本地 qrcode.min.js');
  }
}

async function renderQrIntoModal() {
  els.qrcodeModal.innerHTML = '';
  if (!state.secret) return;
  const uri = buildOtpauthURI(state);
  await ensureQrLib();
  const QR = window.QRCode;
  new QR(els.qrcodeModal, { text: uri, width: 240, height: 240, correctLevel: QR.CorrectLevel.H });
}

els.qrBtn.addEventListener('click', () => {
  try {
    const params = parseInputToParams(els.input.value, state);
    if (!params.secret && !state.secret) throw new Error('缺少 secret');
    if (params.secret) applyParams(params);
    renderQrIntoModal().then(openModal).catch((e) => alert(e.message || String(e)));
  } catch (e) {
    alert(e.message || String(e));
  }
});

els.modalClose.addEventListener('click', closeModal);
els.modalOverlay.addEventListener('click', (e) => {
  if (e.target === els.modalOverlay) closeModal();
});

els.copyUriBtn.addEventListener('click', async () => {
  try {
    const uri = buildOtpauthURI(state);
    await navigator.clipboard.writeText(uri);
    els.copyUriBtn.textContent = '已复制 URI';
    setTimeout(() => (els.copyUriBtn.textContent = '复制 otpauth URI'), 1000);
  } catch (e) { alert(e.message || String(e)); }
});

els.downloadQrBtn.addEventListener('click', () => {
  try {
    const container = els.qrcodeModal;
    const canvas = container.querySelector('canvas');
    if (canvas) {
      const url = canvas.toDataURL('image/png');
      const a = document.createElement('a');
      a.href = url; a.download = 'otpauth-qr.png'; a.click();
      return;
    }
    const table = container.querySelector('table');
    if (table) {
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      const size = 240;
      svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
      svg.setAttribute('width', String(size));
      svg.setAttribute('height', String(size));
      const cells = table.querySelectorAll('td');
      const n = Math.sqrt(cells.length);
      const cellSize = size / n;
      cells.forEach((td, idx) => {
        const x = (idx % n) * cellSize;
        const y = Math.floor(idx / n) * cellSize;
        if (getComputedStyle(td).backgroundColor === 'rgb(0, 0, 0)') {
          const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          rect.setAttribute('x', String(x));
          rect.setAttribute('y', String(y));
          rect.setAttribute('width', String(Math.ceil(cellSize)));
          rect.setAttribute('height', String(Math.ceil(cellSize)));
          rect.setAttribute('fill', '#000');
          svg.appendChild(rect);
        }
      });
      const svgBlob = new Blob([new XMLSerializer().serializeToString(svg)], { type: 'image/svg+xml' });
      const url = URL.createObjectURL(svgBlob);
      const a = document.createElement('a');
      a.href = url; a.download = 'otpauth-qr.svg'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    }
  } catch (e) { alert(e.message || String(e)); }
});

// Attempt to parse on load if hash provided
(function initFromHash() {
  try {
    const hash = decodeURIComponent(location.hash.replace(/^#/, ''));
    if (hash) {
      els.input.value = hash;
      const params = parseInputToParams(hash, state);
      applyParams(params);
      if (params.secret) startLoop();
    }
  } catch {}
})();
