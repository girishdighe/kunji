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
  function renderLocked() {
    const hint = typeof loadedEnvelope.identityHint === 'string' ? esc(loadedEnvelope.identityHint) : '';
    panel.innerHTML = `
      <div class="v-loaded">Vault file loaded.</div>
      <div class="fields">
        <div class="field"><input id="vlIdentity" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${hint}"><label for="vlIdentity">Identity</label></div>
        <div class="field"><input id="vlPass" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="vlPass">Master passphrase</label></div>
      </div>
      <div class="kcv" id="vlKcv" data-state="none"><span class="dot"></span> <span id="vlKcvText">enter identity and passphrase</span></div>
      <button class="btn-primary" id="vlUnlock" type="button">Unlock</button>
      <div class="v-center-link"><button class="link-btn" id="vlOther" type="button">Open a different file</button></div>
      <div class="error" id="vlError"></div>
    `;
    const identityEl = panel.querySelector('#vlIdentity');
    const passEl = panel.querySelector('#vlPass');
    const kcv = panel.querySelector('#vlKcv');
    const kcvText = panel.querySelector('#vlKcvText');

    async function refresh() {
      const id = identityEl.value.trim();
      const pw = passEl.value;
      if (!id || !pw) { kcv.dataset.state = 'none'; kcvText.textContent = 'enter identity and passphrase'; return; }
      kcv.dataset.state = 'none'; kcvText.textContent = 'checking…';
      try {
        const mk = await deriveMasterKey(pw, id);
        if (await computeKcv(mk) === loadedEnvelope.kcv) {
          kcv.dataset.state = 'ok'; kcvText.textContent = 'passphrase matches this vault';
        } else {
          kcv.dataset.state = 'bad'; kcvText.textContent = 'not this vault’s passphrase';
        }
      } catch {
        kcv.dataset.state = 'bad'; kcvText.textContent = 'could not derive key';
      }
    }
    identityEl.addEventListener('change', refresh);
    passEl.addEventListener('change', refresh);

    panel.querySelector('#vlOther').addEventListener('click', () => {
      if (dirty && !confirm('Discard unsaved changes and open a different file?')) return;
      loadedEnvelope = null; wipe(); state = 'NO_VAULT'; render();
    });

    panel.querySelector('#vlUnlock').addEventListener('click', async () => {
      const errEl = panel.querySelector('#vlError');
      errEl.textContent = '';
      const id = identityEl.value.trim();
      const pw = passEl.value;
      if (!id || !pw) { errEl.textContent = 'Identity and passphrase are required.'; return; }
      const btn = panel.querySelector('#vlUnlock');
      btn.disabled = true; btn.textContent = 'Unlocking…';
      try {
        const mk = await deriveMasterKey(pw, id);
        const out = await unlockVault(loadedEnvelope, { masterKey: mk });
        masterKey = mk;
        vault = out;
        sessionIdentity = id;
        identityHintOn = typeof loadedEnvelope.identityHint === 'string';
        dirty = false;
        state = 'UNLOCKED';
        render();
      } catch (e) {
        btn.disabled = false; btn.textContent = 'Unlock';
        if (e && e.name === 'WrongPassphraseError') {
          errEl.textContent = 'That is not the passphrase for this vault.';
        } else if (e && e.name === 'CorruptVaultError') {
          errEl.textContent = 'Could not unlock — the file may be corrupted or from a different passphrase.';
        } else {
          errEl.textContent = 'Could not unlock this vault.';
        }
      }
    });
  }
  function renderUnlocked() { panel.innerHTML = '<p class="v-explain">Unlocked (Task 11)</p>'; }

  render();
}

if (typeof document !== 'undefined') {
  initVaultTab();
}
