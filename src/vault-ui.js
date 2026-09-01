// The Vault tab. References bundle-global functions from vault.js / derive.js
// after concatenation (createVault, addEntry, updateEntry, removeEntry,
// encodeEnvelope, parseEnvelope, unlockVault, deriveMasterKey, computeKcv,
// derivePassword, groupInFours). Never imported by tests.

function initVaultTab() {
  const panel = document.getElementById('tab-vault');
  if (!panel) return;

  const writerId = crypto.randomUUID();

  // Session state. Cleared on lock.
  let state = 'NO_VAULT';        // NO_VAULT | CREATE | LOCKED | UNLOCKED
  let loadedEnvelope = null;     // parsed envelope while LOCKED/UNLOCKED
  let masterKey = null;          // Uint8Array while UNLOCKED
  let vault = null;              // { entries, settings } while UNLOCKED
  let sessionIdentity = '';      // the identity used to unlock/create, for the hint
  let identityHintOn = false;    // write identity into the plaintext envelope?
  let dirty = false;
  let view = 'list';             // list | detail | editor  (within UNLOCKED)
  let selectedId = null;

  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]
  ));

  function wipe() {
    masterKey = null;
    vault = null;
    sessionIdentity = '';
    dirty = false;
    view = 'list';
    selectedId = null;
  }

  function render() {
    if (state === 'NO_VAULT') return renderNoVault();
    if (state === 'CREATE') return renderCreate();
    if (state === 'LOCKED') return renderLocked();
    return renderUnlocked();
  }

  // ---- NO_VAULT ----------------------------------------------------------
  function renderNoVault() {
    panel.innerHTML = `
      <p class="v-explain">A vault stores custom rules, PINs, 2FA recovery codes and
      notes, encrypted with your master passphrase. It is optional — the generator
      works without it.</p>
      <button class="btn-ghost" id="vOpenBtn" type="button">Open vault file&hellip;</button>
      <input type="file" id="vFileInput" accept=".json,application/json" hidden>
      <div class="v-center-link"><button class="link-btn" id="vCreateBtn" type="button">Create a new vault</button></div>
      <div class="error" id="vError"></div>
    `;
    panel.querySelector('#vOpenBtn').addEventListener('click', () => panel.querySelector('#vFileInput').click());
    panel.querySelector('#vFileInput').addEventListener('change', onFilePicked);
    panel.querySelector('#vCreateBtn').addEventListener('click', () => { state = 'CREATE'; render(); });
  }

  async function onFilePicked(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const errEl = panel.querySelector('#vError');
    try {
      const text = await file.text();
      loadedEnvelope = parseEnvelope(text);
      identityHintOn = typeof loadedEnvelope.identityHint === 'string';
      state = 'LOCKED';
      render();
    } catch (e) {
      errEl.textContent = e && e.name === 'BadEnvelopeError'
        ? 'That does not look like a Kunji vault file.'
        : 'Could not read that file.';
    }
  }

  // ---- CREATE ----------------------------------------------------------
  function renderCreate() {
    panel.innerHTML = `
      <div class="fields">
        <div class="field"><input id="vcIdentity" type="text" autocomplete="off" spellcheck="false" placeholder=" "><label for="vcIdentity">Identity</label></div>
        <div class="field"><input id="vcPass" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="vcPass">Master passphrase</label></div>
        <div class="field"><input id="vcConfirm" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="vcConfirm">Confirm passphrase</label></div>
      </div>
      <button class="btn-primary" id="vcCreate" type="button">Create vault</button>
      <div class="v-foot">Same identity + passphrase as the generator.</div>
      <div class="v-center-link"><button class="link-btn" id="vcCancel" type="button">Cancel</button></div>
      <div class="error" id="vcError"></div>
    `;
    panel.querySelector('#vcCancel').addEventListener('click', () => { state = 'NO_VAULT'; render(); });
    panel.querySelector('#vcCreate').addEventListener('click', onCreate);
  }

  async function onCreate() {
    const id = panel.querySelector('#vcIdentity').value.trim();
    const pass = panel.querySelector('#vcPass').value;
    const confirm = panel.querySelector('#vcConfirm').value;
    const errEl = panel.querySelector('#vcError');
    errEl.textContent = '';
    if (!id || !pass) { errEl.textContent = 'Identity and passphrase are required.'; return; }
    if (pass !== confirm) { errEl.textContent = 'The two passphrases do not match.'; return; }
    const btn = panel.querySelector('#vcCreate');
    btn.disabled = true; btn.textContent = 'Creating…';
    try {
      masterKey = await deriveMasterKey(pass, id);
      vault = createVault();
      loadedEnvelope = null;
      sessionIdentity = id;
      identityHintOn = false;
      dirty = true;
      state = 'UNLOCKED';
      render();
    } catch (e) {
      errEl.textContent = 'Could not create the vault.';
      btn.disabled = false; btn.textContent = 'Create vault';
    }
  }

  // ---- LOCKED / UNLOCKED: filled in Tasks 10-13 ----
  function renderLocked() { panel.innerHTML = '<p class="v-explain">Locked (Task 10)</p>'; }
  function renderUnlocked() { panel.innerHTML = '<p class="v-explain">Unlocked (Task 11)</p>'; }

  render();
}

if (typeof document !== 'undefined') {
  initVaultTab();
}
