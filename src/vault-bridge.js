import { entriesForSite } from './vault.js';

// Session hand-off from the Vault tab to the Generate-tab account picker.
// Holds a copy of the currently-active unlocked vault's entries, or null when
// no vault is unlocked. No key / passphrase / ciphertext ever passes through.
let current = null;

function publish(entries) {
  current = Array.isArray(entries) ? entries.map((e) => ({ ...e })) : null;
}
function clear() {
  current = null;
}
function forSite(rawSite) {
  return current ? entriesForSite(current, rawSite) : [];
}
function isActive() {
  return current !== null;
}

export const vaultBridge = { publish, clear, forSite, isActive };
