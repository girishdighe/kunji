export function estimateEntropyBits(length, charsetSize) {
  if (length <= 0) return 0;
  return Math.floor(length * Math.log2(charsetSize));
}

export function groupInFours(str) {
  return str.replace(/(.{4})/g, '$1 ').trim();
}

function initGenerateTab() {
  const $ = (id) => document.getElementById(id);
  const identity = $('identity');
  const master = $('master');
  const site = $('site');
  const account = $('account');
  const lengthEl = $('length');
  const rulesEl = $('rules');
  const kcv = $('kcv');
  const kcvText = $('kcvText');
  const output = $('output');
  const entropyEl = $('entropy');
  const errorEl = $('error');
  const resultLabel = $('resultLabel');
  const generateBtn = $('generateBtn');
  const copyBtn = $('copyBtn');
  const toggleMaster = $('toggleMaster');

  const genPicker = $('genPicker');
  const genPickNote = $('genPickNote');
  let pickedEntry = null;           // { counter, rules, length } while a pick is active
  let pickDebounce = null;

  function clearPick() {
    pickedEntry = null;
    account.parentElement.classList.remove('picked');
    const x = account.parentElement.querySelector('.pick-clear');
    if (x) x.remove();
    genPickNote.hidden = true;
    genPickNote.textContent = '';
  }

  function pickRow(entry) {
    // password path only in this task; sso handled in Task 6
    account.value = entry.account;
    lengthEl.value = String(entry.length ?? 20);
    rulesEl.value = entry.rules ?? 'standard';
    pickedEntry = { counter: entry.counter ?? 1, rules: rulesEl.value, length: parseInt(lengthEl.value, 10) };
    account.parentElement.classList.add('picked');
    if (!account.parentElement.querySelector('.pick-clear')) {
      const x = document.createElement('button');
      x.type = 'button'; x.className = 'pick-clear'; x.textContent = '✕';
      x.addEventListener('click', () => { clearPick(); renderGenPicker(); });
      account.parentElement.appendChild(x);
    }
    renderGenPicker();
  }

  function renderGenPicker() {
    const matches = vaultBridge.forSite(site.value);
    if (!matches.length) { genPicker.hidden = true; genPicker.innerHTML = ''; return; }
    const rows = matches.map((e, i) => {
      const meta = e.type === 'sso'
        ? `via ${escAttr(e.via && e.via.site)}`
        : `${escAttr(e.rules)} &middot; ${escAttr(e.length)}${(e.counter ?? 1) !== 1 ? ` &middot; #${escAttr(e.counter)}` : ''}`;
      return `<div class="gp-row" role="option" data-i="${i}"><span class="gp-name">${escAttr(e.account) || '(no account)'}</span><span class="gp-meta">${meta}</span></div>`;
    }).join('');
    genPicker.innerHTML = `<div class="gp-head">from your vault</div>${rows}`;
    genPicker.hidden = false;
    genPicker.querySelectorAll('.gp-row').forEach((row) => {
      row.addEventListener('click', () => pickRow(matches[Number(row.dataset.i)]));
    });
  }

  function escAttr(s) {
    return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  function scheduleGenPicker() {
    clearTimeout(pickDebounce);
    pickDebounce = setTimeout(renderGenPicker, 200);
  }

  site.addEventListener('change', renderGenPicker);
  site.addEventListener('input', () => { clearPick(); scheduleGenPicker(); });
  site.addEventListener('focus', renderGenPicker);
  account.addEventListener('input', clearPick);

  const REVEAL_SECONDS = 20;
  const CLIPBOARD_SECONDS = 25;
  const revealTimer = {};
  let clipboardTimer = null;
  let plaintext = '';
  let plainGrouped = '';
  // Cache the derived master key so a Generate right after the KCV check does not
  // repeat the ~600k-iteration PBKDF2. Bound to the exact identity+passphrase that
  // produced it, and wiped whenever the passphrase is cleared.
  let mkCache = { id: null, pw: null, key: null };
  const clearMkCache = () => { mkCache = { id: null, pw: null, key: null }; };

  toggleMaster.addEventListener('click', () => {
    const showing = master.type === 'text';
    master.type = showing ? 'password' : 'text';
    toggleMaster.textContent = showing ? 'Show' : 'Hide';
  });

  async function refreshKcv() {
    const id = identity.value.trim();
    const pw = master.value;
    clearMkCache();
    if (!id || !pw) { kcv.dataset.state = 'none'; kcvText.textContent = 'enter identity and passphrase'; return; }
    kcv.dataset.state = 'none';
    kcvText.textContent = 'checking...';
    try {
      const mk = await deriveMasterKey(pw, id);
      const value = await computeKcv(mk);
      mkCache = { id: identity.value, pw: master.value, key: mk };
      kcv.dataset.state = 'ok';
      kcvText.textContent = 'key verified (' + value + ')';
    } catch (e) {
      kcv.dataset.state = 'bad';
      kcvText.textContent = 'could not derive key';
    }
  }
  identity.addEventListener('change', refreshKcv);
  master.addEventListener('change', refreshKcv);

  async function generate() {
    errorEl.textContent = '';
    const length = parseInt(lengthEl.value, 10);
    const rules = rulesEl.value;
    if (!identity.value.trim() || !master.value || !site.value.trim() || !account.value.trim()) {
      errorEl.textContent = 'Identity, passphrase, site, and account are all required.';
      return;
    }
    generateBtn.disabled = true;
    generateBtn.textContent = 'Generating...';
    try {
      const params = { site: site.value, account: account.value, counter: 1, rules, length };
      if (mkCache.key && mkCache.id === identity.value && mkCache.pw === master.value) {
        params.masterKey = mkCache.key;
      } else {
        params.identity = identity.value;
        params.passphrase = master.value;
      }
      plaintext = await derivePassword(params);
      const masked = '\u2022'.repeat(plaintext.length);
      output.dataset.masked = groupInFours(masked);
      plainGrouped = groupInFours(plaintext);
      output.dataset.revealed = '0';
      output.classList.remove('empty');
      output.textContent = output.dataset.masked;
      resultLabel.textContent = 'Password for ' + site.value.trim().toLowerCase();
      const size = ({ 'standard': 74, 'letters-digits': 62, 'max-symbols': 84 })[rules];
      entropyEl.textContent = estimateEntropyBits(length, size) + ' bits of entropy. Unique to this site and counter 1.';
    } catch (e) {
      errorEl.textContent = e.message;
    } finally {
      // Hygiene runs whether or not derivation succeeded: never leave the
      // passphrase or its derived key sitting in the page after a Generate.
      master.value = '';
      master.type = 'password';
      toggleMaster.textContent = 'Show';
      clearMkCache();
      kcv.dataset.state = 'none';
      kcvText.textContent = 'passphrase cleared';
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate';
    }
  }
  generateBtn.addEventListener('click', generate);

  output.addEventListener('click', () => {
    if (output.classList.contains('empty') || !plainGrouped) return;
    if (output.dataset.revealed === '1') {
      output.dataset.revealed = '0';
      output.textContent = output.dataset.masked;
    } else {
      output.dataset.revealed = '1';
      output.textContent = plainGrouped;
      if (revealTimer.t) clearTimeout(revealTimer.t);
      revealTimer.t = setTimeout(() => {
        output.dataset.revealed = '0';
        output.textContent = output.dataset.masked || '';
      }, REVEAL_SECONDS * 1000);
    }
  });

  copyBtn.addEventListener('click', async () => {
    if (!plaintext) return;
    try {
      await navigator.clipboard.writeText(plaintext);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = plaintext;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (_) {}
      document.body.removeChild(ta);
    }
    copyBtn.textContent = 'Copied';
    setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    if (clipboardTimer) clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(async () => {
      try { await navigator.clipboard.writeText(''); } catch (_) {}
    }, CLIPBOARD_SECONDS * 1000);
  });

  return { refreshPicker: renderGenPicker };
}

function initApp() {
  const genBtn = document.getElementById('tabBtnGenerate');
  const vaultBtn = document.getElementById('tabBtnVault');
  const genPanel = document.getElementById('tab-generate');
  const vaultPanel = document.getElementById('tab-vault');

  const gen = initGenerateTab();

  function show(which) {
    const isGen = which === 'generate';
    genPanel.hidden = !isGen;
    vaultPanel.hidden = isGen;
    genBtn.setAttribute('aria-selected', String(isGen));
    vaultBtn.setAttribute('aria-selected', String(!isGen));
    if (isGen && gen && gen.refreshPicker) gen.refreshPicker();
  }
  genBtn.addEventListener('click', () => show('generate'));
  vaultBtn.addEventListener('click', () => show('vault'));
}

if (typeof document !== 'undefined') {
  initApp();
}
