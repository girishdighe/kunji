export function estimateEntropyBits(length, charsetSize) {
  if (length <= 0) return 0;
  return Math.floor(length * Math.log2(charsetSize));
}

export function groupInFours(str) {
  return str.replace(/(.{4})/g, '$1 ').trim();
}

function initUI() {
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

  const REVEAL_SECONDS = 20;
  const CLIPBOARD_SECONDS = 25;
  const revealTimer = {};
  let clipboardTimer = null;
  let plaintext = '';
  let plainGrouped = '';

  toggleMaster.addEventListener('click', () => {
    const showing = master.type === 'text';
    master.type = showing ? 'password' : 'text';
    toggleMaster.textContent = showing ? 'Show' : 'Hide';
  });

  async function refreshKcv() {
    const id = identity.value.trim();
    const pw = master.value;
    if (!id || !pw) { kcv.dataset.state = 'none'; kcvText.textContent = 'enter identity and passphrase'; return; }
    kcv.dataset.state = 'none';
    kcvText.textContent = 'checking...';
    try {
      const mk = await deriveMasterKey(pw, id);
      const value = await computeKcv(mk);
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
      plaintext = await derivePassword({
        identity: identity.value,
        passphrase: master.value,
        site: site.value,
        account: account.value,
        counter: 1,
        rules,
        length,
      });
      const masked = '\u2022'.repeat(plaintext.length);
      output.dataset.masked = groupInFours(masked);
      plainGrouped = groupInFours(plaintext);
      output.dataset.revealed = '0';
      output.classList.remove('empty');
      output.textContent = output.dataset.masked;
      resultLabel.textContent = 'Password for ' + site.value.trim().toLowerCase();
      const size = ({ 'standard': 74, 'letters-digits': 62, 'max-symbols': 84 })[rules];
      entropyEl.textContent = estimateEntropyBits(length, size) + ' bits of entropy. Unique to this site and counter 1.';
      master.value = '';
      master.type = 'password';
      toggleMaster.textContent = 'Show';
      kcv.dataset.state = 'none';
      kcvText.textContent = 'passphrase cleared';
    } catch (e) {
      errorEl.textContent = e.message;
    } finally {
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
}

if (typeof document !== 'undefined') {
  initUI();
}
