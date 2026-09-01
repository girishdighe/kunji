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
  let listQuery = '';
  let sessionMoveNoteShown = false;
  let idleTimer = null;

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
  function markDirty() { dirty = true; if (state === 'UNLOCKED' && view === 'list') renderList(); }

  function clearIdle() { if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; } }

  function armIdle() {
    clearIdle();
    if (state !== 'UNLOCKED') return;
    const mins = (vault && vault.settings && vault.settings.autoLockMinutes) || 5;
    idleTimer = setTimeout(() => {
      // discard unsaved edits — the lock guarantee wins
      lock();
    }, mins * 60 * 1000);
  }

  function lock() {
    clearIdle();
    // keep loadedEnvelope so re-unlock only needs the passphrase
    wipe();
    state = loadedEnvelope ? 'LOCKED' : 'NO_VAULT';
    render();
  }

  async function saveVault() {
    const prevRevision = loadedEnvelope ? (loadedEnvelope.revision || 0) : 0;
    const text = await encodeEnvelope(vault, {
      masterKey,
      identityHint: currentIdentityForHint(),
      prevRevision,
      writerId,
    });
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'kunji-data.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    // Adopt the new revision/updatedAt and clear dirty only after the download
    // has been handed off, so a blocked download leaves the dirty bar and the
    // beforeunload guard in place (spec section 6).
    loadedEnvelope = parseEnvelope(text);
    dirty = false;
    if (!sessionMoveNoteShown) {
      sessionMoveNoteShown = true;
      alert('Saved as kunji-data.json in your downloads. Move it to wherever your sync watches, and overwrite the previous copy.');
    }
    renderList();
  }

  function currentIdentityForHint() {
    if (!identityHintOn) return null;
    return sessionIdentity
      || (loadedEnvelope && typeof loadedEnvelope.identityHint === 'string' ? loadedEnvelope.identityHint : null);
  }

  function renderUnlocked() {
    armIdle();
    if (view === 'detail') return renderDetail();
    if (view === 'editor') return renderEditor();
    return renderList();
  }

  // Shared row markup so the full render and the search re-filter never drift.
  function rowsHtml() {
    const q = (listQuery || '').toLowerCase();
    const html = vault.entries
      .filter((e) => !q || `${e.name} ${e.site} ${e.account}`.toLowerCase().includes(q))
      .map((e) => {
        const meta = e.type === 'sso'
          ? `${esc(e.site)} &middot; via ${esc(e.via && e.via.site)} <span class="v-chip">SSO</span>`
          : `${esc(e.site)} &middot; ${esc(e.account)}`;
        return `<div class="v-row" data-id="${e.id}"><div class="v-name">${esc(e.name) || '(no name)'}</div><div class="v-meta">${meta}</div></div>`;
      })
      .join('');
    return html || `<div class="v-foot">${q ? 'No match.' : 'No entries yet.'}</div>`;
  }

  function bindRowClicks(container) {
    container.querySelectorAll('.v-row').forEach((row) => row.addEventListener('click', () => {
      selectedId = row.dataset.id; view = 'detail'; render();
    }));
  }

  function renderList() {
    panel.innerHTML = `
      <div class="v-bar">
        <span class="v-count">Vault &middot; ${vault.entries.length}</span>
        <button class="link-btn" id="vNew" type="button">+ New</button>
      </div>
      <input class="v-search" id="vSearch" type="text" placeholder="Search…" value="${esc(listQuery || '')}">
      <div id="vRows">${rowsHtml()}</div>
      ${dirty ? '<div class="v-dirty">Unsaved changes<button class="link-btn" id="vSaveTop" type="button" style="color:#f5c518">Save vault</button></div>' : ''}
      <div class="v-foot"><button class="link-btn" id="vSave" type="button">Save vault</button> &middot; <button class="link-btn" id="vLock" type="button">Lock</button></div>
      <label class="v-foot" style="display:block"><input type="checkbox" id="vHint" ${identityHintOn ? 'checked' : ''}> Prefill identity on devices that open this file <span class="v-danger">(anyone with the file can read it)</span></label>
      <div class="error" id="vListError"></div>
    `;

    const search = panel.querySelector('#vSearch');
    search.addEventListener('input', () => {
      listQuery = search.value;
      const c = panel.querySelector('#vRows');
      c.innerHTML = rowsHtml();
      bindRowClicks(c);
    });
    bindRowClicks(panel.querySelector('#vRows'));
    panel.querySelector('#vNew').addEventListener('click', () => { selectedId = null; view = 'editor'; render(); });
    panel.querySelector('#vSave').addEventListener('click', () => saveVault().catch(showSaveError));
    if (panel.querySelector('#vSaveTop')) panel.querySelector('#vSaveTop').addEventListener('click', () => saveVault().catch(showSaveError));
    panel.querySelector('#vHint').addEventListener('change', (ev) => { identityHintOn = ev.target.checked; markDirty(); });
    panel.querySelector('#vLock').addEventListener('click', () => {
      if (dirty && !confirm('Discard unsaved changes and lock?')) return;
      lock();
    });
  }

  function showSaveError(e) {
    const el = panel.querySelector('#vListError');
    if (el) el.textContent = 'Save was blocked — allow downloads for this page and try again.';
  }

  function selectedEntry() { return vault.entries.find((e) => e.id === selectedId) || null; }

  async function renderDetail() {
    const e = selectedEntry();
    if (!e) { view = 'list'; return renderList(); }

    if (e.type === 'sso') {
      panel.innerHTML = `
        <div class="v-bar"><button class="link-btn" id="vBack" type="button">&lsaquo; Vault</button><button class="link-btn" id="vEdit" type="button">Edit</button></div>
        <div class="title" style="font-size:18px">${esc(e.name)}</div>
        <div class="v-meta">${esc(e.site)} &middot; ${esc(e.account)}</div>
        <div class="v-sec"><div class="v-h">Log in via</div><div>${esc(e.via && e.via.site)} &middot; ${esc(e.via && e.via.account)}</div></div>
        <div class="v-sec"><div class="v-h">Notes</div><div class="v-meta">${esc(e.notes) || '—'}</div></div>
      `;
      panel.querySelector('#vBack').addEventListener('click', () => { view = 'list'; render(); });
      panel.querySelector('#vEdit').addEventListener('click', () => { view = 'editor'; render(); });
      return;
    }

    const codes = Array.isArray(e.recoveryCodes) ? e.recoveryCodes : [];
    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="vBack" type="button">&lsaquo; Vault</button><button class="link-btn" id="vEdit" type="button">Edit</button></div>
      <div class="title" style="font-size:18px">${esc(e.name)}</div>
      <div class="v-meta">${esc(e.site)} &middot; ${esc(e.account)}</div>
      <div style="margin:8px 0">
        <span class="v-chip">${esc(e.profile)}</span><span class="v-chip">len ${esc(e.length)}</span><span class="v-chip">${esc(e.rules)}</span><span class="v-chip">counter ${esc(e.counter)}</span>
      </div>
      <div class="result-value empty" id="vPw">not derived</div>
      <div><button class="link-btn" id="vReveal" type="button">Reveal</button> &middot; <button class="link-btn" id="vCopy" type="button">Copy</button></div>
      <div class="error" id="vDetailError"></div>
      <div class="v-sec"><div class="v-h">Notes</div><div class="v-meta">${esc(e.notes) || '—'}</div></div>
      <div class="v-sec"><div class="v-h">Recovery codes &middot; ${codes.length}</div><div id="vCodes" class="v-meta">${codes.length ? '<button class="link-btn" id="vShowCodes" type="button">Reveal / copy</button>' : '—'}</div></div>
      <div class="v-sec"><div class="v-h">TOTP secret</div><div class="v-meta">${e.totp ? '&bull;&bull;&bull;&bull; <button class="link-btn" id="vTotpCopy" type="button">copy</button>' : '—'}</div></div>
    `;

    panel.querySelector('#vBack').addEventListener('click', () => { view = 'list'; render(); });
    panel.querySelector('#vEdit').addEventListener('click', () => { view = 'editor'; render(); });

    const pwEl = panel.querySelector('#vPw');
    const errEl = panel.querySelector('#vDetailError');
    let plaintext = '';
    let revealTimer = null;

    async function derive() {
      if (plaintext) return plaintext;
      plaintext = await derivePassword({
        masterKey, site: e.site, account: e.account,
        counter: e.counter, rules: e.rules, length: e.length,
      });
      return plaintext;
    }

    panel.querySelector('#vReveal').addEventListener('click', async () => {
      errEl.textContent = '';
      try {
        const pw = await derive();
        pwEl.classList.remove('empty');
        pwEl.textContent = groupInFours(pw);
        if (revealTimer) clearTimeout(revealTimer);
        revealTimer = setTimeout(() => {
          pwEl.textContent = groupInFours('•'.repeat(pw.length));
        }, (vault.settings.revealSeconds || 20) * 1000);
      } catch (err) { errEl.textContent = err.message; }
    });

    panel.querySelector('#vCopy').addEventListener('click', async () => {
      errEl.textContent = '';
      try {
        const pw = await derive();
        try { await navigator.clipboard.writeText(pw); }
        catch {
          const ta = document.createElement('textarea'); ta.value = pw;
          document.body.appendChild(ta); ta.select();
          try { document.execCommand('copy'); } catch (_) {}
          document.body.removeChild(ta);
        }
        const btn = panel.querySelector('#vCopy');
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        setTimeout(async () => { try { await navigator.clipboard.writeText(''); } catch (_) {} },
          (vault.settings.clipboardClearSeconds || 25) * 1000);
      } catch (err) { errEl.textContent = err.message; }
    });

    const showCodes = panel.querySelector('#vShowCodes');
    if (showCodes) showCodes.addEventListener('click', () => {
      panel.querySelector('#vCodes').innerHTML = codes.map((c) => esc(c)).join('<br>');
    });
    const totpCopy = panel.querySelector('#vTotpCopy');
    if (totpCopy) totpCopy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(e.totp); totpCopy.textContent = 'copied'; } catch (_) {}
    });
  }

  function renderEditor() {
    const existing = selectedEntry(); // null when creating
    const e = existing || makeEntry({ type: 'password' });
    const isSso = e.type === 'sso';

    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="edCancel" type="button">&lsaquo; Cancel</button><button class="link-btn" id="edDone" type="button">Done</button></div>
      <div class="fields">
        <div class="field"><input id="edName" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.name)}"><label for="edName">Name</label></div>
        <div class="field select-wrap">
          <select id="edType">
            <option value="password" ${isSso ? '' : 'selected'}>password</option>
            <option value="sso" ${isSso ? 'selected' : ''}>sso</option>
          </select>
          <label for="edType">Type</label>
        </div>
        <div class="field"><input id="edSite" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.site)}"><label for="edSite">Site or app</label></div>
        <div class="field"><input id="edAccount" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.account)}"><label for="edAccount">Account</label></div>
        <div id="edPwFields" ${isSso ? 'hidden' : ''}>
          <div class="v-editrow">
            <div class="field"><input id="edLength" type="text" inputmode="numeric" placeholder=" " value="${esc(e.length ?? 20)}"><label for="edLength">Length</label></div>
            <div class="field select-wrap">
              <select id="edRules">
                <option value="standard" ${e.rules === 'letters-digits' || e.rules === 'max-symbols' ? '' : 'selected'}>standard</option>
                <option value="letters-digits" ${e.rules === 'letters-digits' ? 'selected' : ''}>letters-digits</option>
                <option value="max-symbols" ${e.rules === 'max-symbols' ? 'selected' : ''}>max-symbols</option>
              </select>
              <label for="edRules">Rules</label>
            </div>
            <div class="field"><input id="edCounter" type="text" inputmode="numeric" placeholder=" " value="${esc(e.counter ?? 1)}"><label for="edCounter">Counter</label></div>
          </div>
          <div class="field"><input id="edTotp" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.totp ?? '')}"><label for="edTotp">TOTP secret (optional)</label></div>
          <div class="field"><textarea id="edCodes" rows="3" placeholder=" ">${esc((e.recoveryCodes || []).join('\n'))}</textarea><label for="edCodes">Recovery codes (one per line)</label></div>
        </div>
        <div id="edSsoFields" ${isSso ? '' : 'hidden'}>
          <div class="field"><input id="edViaSite" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.via && e.via.site)}"><label for="edViaSite">Log in via — site</label></div>
          <div class="field"><input id="edViaAccount" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.via && e.via.account)}"><label for="edViaAccount">Log in via — account</label></div>
        </div>
        <div class="field"><textarea id="edNotes" rows="2" placeholder=" ">${esc(e.notes)}</textarea><label for="edNotes">Notes</label></div>
      </div>
      ${existing ? '<div class="v-center-link"><button class="link-btn v-danger" id="edDelete" type="button">Delete entry</button></div>' : ''}
      <div class="error" id="edError"></div>
    `;

    const typeSel = panel.querySelector('#edType');
    typeSel.addEventListener('change', () => {
      const sso = typeSel.value === 'sso';
      panel.querySelector('#edPwFields').hidden = sso;
      panel.querySelector('#edSsoFields').hidden = !sso;
    });

    panel.querySelector('#edCancel').addEventListener('click', () => {
      view = existing ? 'detail' : 'list'; render();
    });

    if (existing) panel.querySelector('#edDelete').addEventListener('click', () => {
      if (!confirm('Delete this entry?')) return;
      vault = removeEntry(vault, existing.id);
      markDirty();
      selectedId = null; view = 'list'; render();
    });

    panel.querySelector('#edDone').addEventListener('click', () => {
      const errEl = panel.querySelector('#edError');
      errEl.textContent = '';
      const type = typeSel.value;
      const name = panel.querySelector('#edName').value.trim();
      const site = panel.querySelector('#edSite').value.trim();
      const account = panel.querySelector('#edAccount').value.trim();
      if (!name || !site || !account) { errEl.textContent = 'Name, site, and account are required.'; return; }

      let patch;
      if (type === 'sso') {
        patch = {
          type: 'sso', name, site, account,
          via: {
            site: panel.querySelector('#edViaSite').value.trim(),
            account: panel.querySelector('#edViaAccount').value.trim(),
          },
          notes: panel.querySelector('#edNotes').value,
        };
      } else {
        const length = parseInt(panel.querySelector('#edLength').value, 10);
        const counter = parseInt(panel.querySelector('#edCounter').value, 10);
        if (!Number.isInteger(length) || length < 8 || length > 64) { errEl.textContent = 'Length must be a whole number from 8 to 64.'; return; }
        if (!Number.isInteger(counter) || counter < 1) { errEl.textContent = 'Counter must be a whole number of at least 1.'; return; }
        patch = {
          type: 'password', name, site, account,
          length, counter, rules: panel.querySelector('#edRules').value,
          profile: 'v1',
          totp: panel.querySelector('#edTotp').value.trim() || null,
          recoveryCodes: panel.querySelector('#edCodes').value.split('\n').map((s) => s.trim()).filter(Boolean),
          notes: panel.querySelector('#edNotes').value,
        };
      }

      const dup = vault.entries.find((x) => x.id !== (existing && existing.id)
        && x.site.toLowerCase() === site.toLowerCase()
        && x.account.toLowerCase() === account.toLowerCase());
      if (dup && !confirm('An entry for this site and account already exists. Save anyway?')) return;

      if (existing) {
        if (existing.type === type) {
          vault = updateEntry(vault, existing.id, patch);
        } else {
          // Type changed: rebuild the entry from scratch so no fields from the
          // old type (counter/rules/totp/recoveryCodes, or a stale via) linger.
          const rebuilt = { ...makeEntry(patch), id: existing.id, updatedAt: new Date().toISOString() };
          vault = { ...vault, entries: vault.entries.map((x) => (x.id === existing.id ? rebuilt : x)) };
        }
        selectedId = existing.id;
        view = 'detail';
      } else {
        vault = addEntry(vault, patch);
        selectedId = vault.entries[vault.entries.length - 1].id;
        view = 'detail';
      }
      markDirty();
      render();
    });
  }

  window.addEventListener('beforeunload', (e) => {
    if (dirty) { e.preventDefault(); e.returnValue = ''; }
  });

  ['keydown', 'pointerdown'].forEach((evt) =>
    panel.addEventListener(evt, () => { if (state === 'UNLOCKED') armIdle(); }),
  );

  render();
}

if (typeof document !== 'undefined') {
  initVaultTab();
}
