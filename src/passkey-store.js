// Per-device passkey records, keyed by the vault's KCV so a record is only
// offered for the file it belongs to. localStorage only; never written to the
// vault file, never cached by the service worker.

const PREFIX = 'kunji.passkey.';

function ls() {
  try { return globalThis.localStorage || null; } catch { return null; }
}

export function hasPasskey(kcv) {
  const s = ls();
  try { return !!s && s.getItem(PREFIX + kcv) !== null; } catch { return false; }
}

export function loadPasskey(kcv) {
  const s = ls();
  if (!s) return null;
  try {
    const raw = s.getItem(PREFIX + kcv);
    if (raw == null) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

export function savePasskey(kcv, record) {
  const s = ls();
  try { if (s) s.setItem(PREFIX + kcv, JSON.stringify(record)); } catch { /* quota / private mode */ }
}

export function removePasskey(kcv) {
  const s = ls();
  try { if (s) s.removeItem(PREFIX + kcv); } catch { /* ignore */ }
}
