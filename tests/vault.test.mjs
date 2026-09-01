import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BadEnvelopeError, WrongPassphraseError, CorruptVaultError,
  VAULT_FORMAT, VAULT_V, VAULT_AAD,
  randomBytes, newDecoyBytes,
} from '../src/vault.js';
import { base64ToBytes, fromUtf8 } from '../src/encoding.js';

test('typed errors have distinct names and are Error subclasses', () => {
  for (const E of [BadEnvelopeError, WrongPassphraseError, CorruptVaultError]) {
    const e = new E('x');
    assert.ok(e instanceof Error);
    assert.equal(e.message, 'x');
  }
  assert.equal(new BadEnvelopeError().name, 'BadEnvelopeError');
  assert.equal(new WrongPassphraseError().name, 'WrongPassphraseError');
  assert.equal(new CorruptVaultError().name, 'CorruptVaultError');
});

test('envelope constants are the frozen values', () => {
  assert.equal(VAULT_FORMAT, 'kunji-data');
  assert.equal(VAULT_V, 1);
  assert.equal(fromUtf8(VAULT_AAD), 'kunji-vault-v1');
});

test('randomBytes returns n fresh bytes', () => {
  const a = randomBytes(16);
  const b = randomBytes(16);
  assert.equal(a.length, 16);
  assert.notEqual(
    Buffer.from(a).toString('hex'),
    Buffer.from(b).toString('hex'),
    'two calls should almost never collide',
  );
});

test('newDecoyBytes(ctLen) has 4-byte kcv, 12-byte iv, ctLen-byte ct, all base64', () => {
  const d = newDecoyBytes(320);
  assert.equal(base64ToBytes(d.kcv).length, 4);
  assert.equal(base64ToBytes(d.iv).length, 12);
  assert.equal(base64ToBytes(d.ct).length, 320);
  const d2 = newDecoyBytes(320);
  assert.notEqual(d.ct, d2.ct, 'decoy ct is random per call');
});

import {
  createVault, makeEntry, addEntry, updateEntry, removeEntry, visibleEntries,
} from '../src/vault.js';

test('createVault is empty with the default settings', () => {
  const v = createVault();
  assert.deepEqual(v.entries, []);
  assert.equal(v.settings.autoLockMinutes, 5);
  assert.equal(v.settings.clipboardClearSeconds, 25);
  assert.equal(v.settings.revealSeconds, 20);
  assert.equal(v.settings.defaultRules, 'standard');
  assert.equal(v.settings.defaultLength, 20);
});

test('makeEntry: password defaults', () => {
  const e = makeEntry({ name: 'GitHub', site: 'github.com', account: 'me' });
  assert.equal(e.type, 'password');
  assert.equal(e.profile, 'v1');
  assert.equal(e.counter, 1);
  assert.equal(e.length, 20);
  assert.equal(e.rules, 'standard');
  assert.equal(e.totp, null);
  assert.deepEqual(e.recoveryCodes, []);
  assert.match(e.id, /^[0-9a-f-]{36}$/);
  assert.ok(e.updatedAt);
});

test('makeEntry: sso shape, no derivation fields', () => {
  const e = makeEntry({ type: 'sso', name: 'News', site: 'news.example.com', account: 'me', via: { site: 'google.com', account: 'me' } });
  assert.equal(e.type, 'sso');
  assert.deepEqual(e.via, { site: 'google.com', account: 'me' });
  assert.equal(e.counter, undefined);
  assert.equal(e.rules, undefined);
});

test('makeEntry: caller cannot override id via partial', () => {
  const e = makeEntry({ id: 'attacker', name: 'x' });
  assert.notEqual(e.id, 'attacker');
});

test('addEntry appends a new entry without mutating the input', () => {
  const v0 = createVault();
  const v1 = addEntry(v0, { name: 'A', site: 's', account: 'a' });
  assert.equal(v0.entries.length, 0);
  assert.equal(v1.entries.length, 1);
  assert.equal(v1.entries[0].name, 'A');
});

test('updateEntry patches by id, bumps updatedAt, keeps id', async () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const id = v.entries[0].id;
  const before = v.entries[0].updatedAt;
  await new Promise((r) => setTimeout(r, 2));
  v = updateEntry(v, id, { name: 'A2', id: 'nope' });
  assert.equal(v.entries[0].name, 'A2');
  assert.equal(v.entries[0].id, id);
  assert.notEqual(v.entries[0].updatedAt, before);
});

test('removeEntry replaces the entry with a tombstone, in place', () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  v = addEntry(v, { name: 'B', site: 's2', account: 'b' });
  const id = v.entries[0].id;
  v = removeEntry(v, id);
  assert.equal(v.entries.length, 2, 'array length unchanged');
  const t = v.entries.find((e) => e.id === id);
  assert.deepEqual(Object.keys(t).sort(), ['deleted', 'id', 'updatedAt']);
  assert.equal(t.deleted, true);
  // idempotent
  const again = removeEntry(v, id).entries.find((e) => e.id === id);
  assert.equal(again.deleted, true);
});

test('visibleEntries filters tombstones, preserves order, does not mutate', () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  v = addEntry(v, { name: 'B', site: 's2', account: 'b' });
  v = addEntry(v, { name: 'C', site: 's3', account: 'c' });
  v = removeEntry(v, v.entries[1].id);
  const vis = visibleEntries(v);
  assert.deepEqual(vis.map((e) => e.name), ['A', 'C']);
  assert.equal(v.entries.length, 3, 'source untouched');
});

import { encodeEnvelope } from '../src/vault.js';
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS, PROFILES } from '../src/derive.js';
import { hexToBytes, base64ToBytes as b64 } from '../src/encoding.js';

const MK = hexToBytes('ab'.repeat(31) + '12');

test('encodeEnvelope produces a valid, complete envelope string', async () => {
  const vault = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const text = await encodeEnvelope(vault, { masterKey: MK, prevRevision: 41, writerId: 'w-1' });
  const env = JSON.parse(text);
  assert.equal(env.format, 'kunji-data');
  assert.equal(env.v, 1);
  assert.equal(env.kdf, `pbkdf2-sha512-${PBKDF2_ITERATIONS}`);
  assert.equal(env.identityHint, null);
  assert.equal(env.kcv, await computeKcv(MK));
  assert.equal(b64(env.iv).length, 12);
  assert.ok(b64(env.ct).length > 16);
  assert.equal(b64(env.decoy.kcv).length, 4);
  assert.equal(b64(env.decoy.iv).length, 12);
  assert.equal(b64(env.decoy.ct).length, b64(env.ct).length, 'decoy ct matches real ct length');
  assert.equal(env.revision, 42);
  assert.equal(env.lastWriter, 'w-1');
  assert.match(env.updatedAt, /^\d{4}-\d\d-\d\dT/);
  assert.ok(text.endsWith('\n'));
});

test('encodeEnvelope writes identityHint only when given', async () => {
  const v = createVault();
  const withHint = JSON.parse(await encodeEnvelope(v, { masterKey: MK, identityHint: 'me@x.com', writerId: 'w' }));
  assert.equal(withHint.identityHint, 'me@x.com');
});

test('encodeEnvelope uses a fresh IV each call', async () => {
  const v = createVault();
  const a = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  const b = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ct, b.ct);
});

test('encodeEnvelope defaults prevRevision to 0 -> revision 1', async () => {
  const env = JSON.parse(await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' }));
  assert.equal(env.revision, 1);
});

import { parseEnvelope, unlockVault } from '../src/vault.js';

const OTHER_MK = hexToBytes('cd'.repeat(32));

test('parseEnvelope accepts a well-formed envelope', async () => {
  const text = await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' });
  const env = parseEnvelope(text);
  assert.equal(env.format, 'kunji-data');
});

test('parseEnvelope rejects non-JSON, wrong format, wrong version, missing fields', () => {
  assert.throws(() => parseEnvelope('not json'), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ format: 'other', v: 1 })), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ format: 'kunji-data', v: 2 })), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ format: 'kunji-data', v: 1 })), BadEnvelopeError);
});

test('unlockVault round-trips entries and settings', async () => {
  const v = addEntry(createVault(), { name: 'GitHub', site: 'github.com', account: 'me', notes: 'hi' });
  const env = parseEnvelope(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  const out = await unlockVault(env, { masterKey: MK });
  assert.equal(out.entries.length, 1);
  assert.equal(out.entries[0].name, 'GitHub');
  assert.equal(out.entries[0].notes, 'hi');
  assert.equal(out.settings.autoLockMinutes, 5);
});

test('unlockVault throws WrongPassphraseError on KCV mismatch', async () => {
  const env = parseEnvelope(await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' }));
  await assert.rejects(() => unlockVault(env, { masterKey: OTHER_MK }), WrongPassphraseError);
});

test('unlockVault throws CorruptVaultError when the ciphertext is damaged', async () => {
  const env = parseEnvelope(await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' }));
  const bad = { ...env, ct: bytesToBase64Local(flipFirstByte(b64(env.ct))) };
  await assert.rejects(() => unlockVault(bad, { masterKey: MK }), CorruptVaultError);
});

function flipFirstByte(bytes) { const c = bytes.slice(); c[0] ^= 1; return c; }
function bytesToBase64Local(bytes) { return Buffer.from(bytes).toString('base64'); }

test('frozen decrypt vector: fixed vaultKey/iv/ct/aad -> known plaintext', async () => {
  const { aesGcmDecrypt } = await import('../src/webcrypto.js');
  const { utf8: u, hexToBytes: h, fromUtf8: f } = await import('../src/encoding.js');
  const vaultKey = h('0000000000000000000000000000000000000000000000000000000000000000');
  const iv = h('000000000000000000000000');
  const ct = h('b58525533912020b746cff88e7dfbf6b171477a359c15956ebd988f34d793ed45791dd65c34d2f2e614c3939');
  const plain = await aesGcmDecrypt(vaultKey, iv, ct, u('kunji-vault-v1'));
  assert.equal(f(plain), '{"entries":[],"settings":{}}');
});

test('parseEnvelope rejects a missing or malformed decoy section', () => {
  const base = { format: 'kunji-data', v: 1, kcv: 'x', iv: 'y', ct: 'z' };
  assert.throws(() => parseEnvelope(JSON.stringify(base)), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ ...base, decoy: {} })), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ ...base, decoy: { kcv: 'a', iv: 'b' } })), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ ...base, decoy: { kcv: 1, iv: 'b', ct: 'c' } })), BadEnvelopeError);
});

// An envelope that clears the KCV gate and decrypts cleanly to `plaintextBytes`,
// so unlockVault reaches its JSON.parse / shape-check stage.
async function envelopeDecryptingTo(plaintextBytes) {
  const { aesGcmEncrypt } = await import('../src/webcrypto.js');
  const vaultKey = await deriveVaultKey(MK);
  const iv = new Uint8Array(12);
  const ct = await aesGcmEncrypt(vaultKey, iv, plaintextBytes, VAULT_AAD);
  return {
    format: 'kunji-data',
    v: 1,
    kcv: await computeKcv(MK),
    iv: Buffer.from(iv).toString('base64'),
    ct: Buffer.from(ct).toString('base64'),
    decoy: { kcv: 'AAAA', iv: 'AAAA', ct: 'AAAA' },
  };
}

test('unlockVault throws CorruptVaultError when the decrypted plaintext is not JSON', async () => {
  const { utf8: u } = await import('../src/encoding.js');
  const env = await envelopeDecryptingTo(u('this is not json'));
  await assert.rejects(() => unlockVault(env, { masterKey: MK }), CorruptVaultError);
});

test('unlockVault throws CorruptVaultError when the plaintext JSON has the wrong shape', async () => {
  const { utf8: u } = await import('../src/encoding.js');
  const env = await envelopeDecryptingTo(u('{"entries":"nope","settings":{}}'));
  await assert.rejects(() => unlockVault(env, { masterKey: MK }), CorruptVaultError);
});

test('unlockVault rejects settings that is null or an array (typeof null === "object" gap)', async () => {
  const { utf8: u } = await import('../src/encoding.js');
  for (const bad of ['{"entries":[],"settings":null}', '{"entries":[],"settings":[]}']) {
    const env = await envelopeDecryptingTo(u(bad));
    await assert.rejects(() => unlockVault(env, { masterKey: MK }), CorruptVaultError);
  }
});

test('parseEnvelope rejects a missing, non-integer, or negative revision', async () => {
  const good = JSON.parse(await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' }));
  assert.equal(parseEnvelope(JSON.stringify(good)).revision, 1);
  for (const rev of [undefined, '5', 1.5, -1, null]) {
    const bad = { ...good };
    if (rev === undefined) delete bad.revision; else bad.revision = rev;
    assert.throws(() => parseEnvelope(JSON.stringify(bad)), BadEnvelopeError);
  }
});

test('encodeEnvelope stamps the v1 profile kdf tag', async () => {
  const v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const env = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  assert.equal(env.kdf, PROFILES.v1.kdfTag);
});

test('parseEnvelope rejects a header with an unknown kdf', async () => {
  const v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const env = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  env.kdf = 'argon2id-m65536-t3-p1';
  assert.throws(() => parseEnvelope(JSON.stringify(env)), /unknown KDF/);
});

test('parseEnvelope still accepts the current pbkdf2 tag', async () => {
  const v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const text = await encodeEnvelope(v, { masterKey: MK, writerId: 'w' });
  assert.doesNotThrow(() => parseEnvelope(text));
});

test('makeEntry sso branch drops stray password fields; password branch drops stray via', () => {
  const sso = makeEntry({
    type: 'sso', name: 'N', site: 's', account: 'a', via: { site: 'g', account: 'x' },
    counter: 9, length: 40, rules: 'max-symbols', totp: 'SECRET', recoveryCodes: ['c1'], profile: 'v1',
  });
  assert.equal(sso.type, 'sso');
  for (const k of ['counter', 'length', 'rules', 'totp', 'recoveryCodes', 'profile']) {
    assert.ok(!(k in sso), `sso entry must not carry ${k}`);
  }
  const pw = makeEntry({ type: 'password', name: 'N', site: 's', account: 'a', via: { site: 'g', account: 'x' } });
  assert.equal(pw.type, 'password');
  assert.ok(!('via' in pw), 'password entry must not carry via');
});

import { entriesForSite, resolveEntryForPick } from '../src/vault.js';

const PW = (over = {}) => makeEntry({ type: 'password', name: 'n', site: 's', account: 'a', ...over });
const SSO = (over = {}) => makeEntry({ type: 'sso', name: 'n', site: 's', account: 'a', via: { site: 'g', account: 'x' }, ...over });

test('entriesForSite matches on normalised site equality only', () => {
  const list = [PW({ site: 'GitHub.com', account: 'me' }), PW({ site: '  github.com ', account: 'work' }), PW({ site: 'gitlab.com' })];
  const hit = entriesForSite(list, 'github.com');
  assert.equal(hit.length, 2);
  assert.deepEqual(hit.map((e) => e.account), ['me', 'work']); // input order preserved
});

test('entriesForSite: empty / whitespace / no-match returns []', () => {
  const list = [PW({ site: 'github.com' })];
  assert.deepEqual(entriesForSite(list, ''), []);
  assert.deepEqual(entriesForSite(list, '   '), []);
  assert.deepEqual(entriesForSite(list, 'example.com'), []);
});

test('entriesForSite does not mutate the input array or entries', () => {
  const list = [PW({ site: 'x.com' })];
  const snapshot = JSON.stringify(list);
  entriesForSite(list, 'x.com');
  assert.equal(JSON.stringify(list), snapshot);
});

test('resolveEntryForPick: password entry resolves to itself', () => {
  const e = PW({ site: 'x.com', account: 'me' });
  assert.equal(resolveEntryForPick([e], e), e);
});

test('resolveEntryForPick: sso entry resolves to the underlying entry', () => {
  const google = PW({ site: 'google.com', account: 'me@gmail.com' });
  const news = SSO({ site: 'news.example.com', account: 'me', via: { site: 'Google.com', account: 'ME@gmail.com' } });
  assert.equal(resolveEntryForPick([google, news], news), google);
});

test('resolveEntryForPick: sso with no matching underlying entry returns null', () => {
  const news = SSO({ via: { site: 'google.com', account: 'gone' } });
  assert.equal(resolveEntryForPick([news], news), null);
});

test('resolveEntryForPick: sso with blank via returns null', () => {
  const news = SSO({ via: { site: '', account: '' } });
  assert.equal(resolveEntryForPick([news], news), null);
});

import { padPlaintextTo } from '../src/vault.js';
import { utf8 as _utf8 } from '../src/encoding.js';

test('padPlaintextTo returns JSON text of exactly the target byte length, parsing back to obj', () => {
  const obj = { entries: [], settings: { autoLockMinutes: 5 } };
  for (const target of [400, 813, 2048]) {
    const text = padPlaintextTo(obj, target);
    assert.equal(typeof text, 'string');
    assert.equal(_utf8(text).length, target);
    assert.deepEqual(JSON.parse(text), obj);
  }
});

test('padPlaintextTo can hit any target >= the raw length (no dead zone)', () => {
  const obj = { entries: [{ id: 'a' }], settings: {} };
  const raw = _utf8(JSON.stringify(obj)).length;
  for (const target of [raw, raw + 1, raw + 5, raw + 9, raw + 200]) {
    assert.equal(_utf8(padPlaintextTo(obj, target)).length, target);
    assert.deepEqual(JSON.parse(padPlaintextTo(obj, target)), obj);
  }
});

test('padPlaintextTo throws when the object is already larger than the target', () => {
  const obj = { entries: [{ id: 'x', name: 'n'.repeat(40) }], settings: {} };
  const raw = _utf8(JSON.stringify(obj)).length;
  assert.throws(() => padPlaintextTo(obj, raw - 5));
});

import { openVault } from '../src/vault.js';

const RMK = hexToBytes('ab'.repeat(31) + '12'); // same 32 bytes as MK
const DMK = hexToBytes('cd'.repeat(32));        // same as OTHER_MK

test('openVault routes to the real slot for the real passphrase', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const env = parseEnvelope(await encodeEnvelope(real, { masterKey: RMK, writerId: 'w' }));
  const out = await openVault(env, { masterKey: RMK });
  assert.equal(out.slot, 'real');
  assert.equal(out.entries[0].name, 'R');
  assert.equal(out._pad, undefined);
});

test('openVault throws WrongPassphraseError for a passphrase matching neither slot', async () => {
  const env = parseEnvelope(await encodeEnvelope(createVault(), { masterKey: RMK, writerId: 'w' }));
  await assert.rejects(() => openVault(env, { masterKey: hexToBytes('ef'.repeat(32)) }), WrongPassphraseError);
});

test('openVault on a decoy-less (random filler) envelope: real works, decoy passphrase rejects', async () => {
  const env = parseEnvelope(await encodeEnvelope(addEntry(createVault(), { name: 'R', site: 'r', account: 'r' }), { masterKey: RMK, writerId: 'w' }));
  assert.equal((await openVault(env, { masterKey: RMK })).slot, 'real');
  await assert.rejects(() => openVault(env, { masterKey: DMK }), WrongPassphraseError);
});

// helper: build an envelope carrying BOTH a real and a decoy vault
async function envWithDecoy(realVault, realMK, decoyVault, decoyMK) {
  const text = await encodeEnvelope(realVault, {
    masterKey: realMK, writerId: 'w',
    decoy: { vault: decoyVault, masterKey: decoyMK },
  });
  return parseEnvelope(text);
}

test('openVault routes to the decoy slot for the decoy passphrase', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd' });
  const env = await envWithDecoy(real, RMK, decoy, DMK);
  const out = await openVault(env, { masterKey: DMK });
  assert.equal(out.slot, 'decoy');
  assert.equal(out.entries[0].name, 'D');
  assert.equal(out._pad, undefined);
});

test('openVault opens the decoy even if the real ct is damaged', async () => {
  const env = await envWithDecoy(createVault(), RMK, addEntry(createVault(), { name: 'D', site: 'd', account: 'd' }), DMK);
  const bad = Buffer.from(env.ct, 'base64'); bad[0] ^= 1;
  env.ct = bad.toString('base64');
  const out = await openVault(env, { masterKey: DMK });
  assert.equal(out.slot, 'decoy');
  assert.equal(out.entries[0].name, 'D');
});

test('encodeEnvelope with a decoy: both slots decrypt, ct lengths equal, decoy kcv correct', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r', notes: 'the real one is longer '.repeat(4) });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd' });
  const text = await encodeEnvelope(real, { masterKey: RMK, writerId: 'w', decoy: { vault: decoy, masterKey: DMK } });
  const env = JSON.parse(text);
  assert.equal(b64(env.ct).length, b64(env.decoy.ct).length, 'ct lengths equal');
  assert.equal(env.decoy.kcv, await computeKcv(DMK));
  assert.equal(b64(env.decoy.iv).length, 12);
  const r = await openVault(env, { masterKey: RMK });
  const d = await openVault(env, { masterKey: DMK });
  assert.equal(r.entries[0].name, 'R');
  assert.equal(d.entries[0].name, 'D');
  assert.equal(r._pad, undefined);
  assert.equal(d._pad, undefined);
});

test('encodeEnvelope with a decoy pads whichever plaintext is shorter', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd', notes: 'x'.repeat(500) });
  const env = JSON.parse(await encodeEnvelope(real, { masterKey: RMK, writerId: 'w', decoy: { vault: decoy, masterKey: DMK } }));
  assert.equal(b64(env.ct).length, b64(env.decoy.ct).length);
});

test('encodeEnvelope with a decoy: ct lengths equal even when the two vaults differ by only a few bytes', async () => {
  // Regression: the old _pad-key scheme had a 1..9 byte "dead zone" this hits.
  const real = addEntry(createVault(), { name: 'Amazon', site: 'amazon.com', account: 'me' });
  const decoy = addEntry(createVault(), { name: 'Netflix', site: 'netflix.com', account: 'me' });
  const env = JSON.parse(await encodeEnvelope(real, { masterKey: RMK, writerId: 'w', decoy: { vault: decoy, masterKey: DMK } }));
  assert.equal(b64(env.ct).length, b64(env.decoy.ct).length);
  assert.equal((await openVault(env, { masterKey: RMK })).entries[0].name, 'Amazon');
  assert.equal((await openVault(env, { masterKey: DMK })).entries[0].name, 'Netflix');
});

test('encodeEnvelope with a decoy: ct length is a multiple of PAD_BLOCK (+16 tag), giving duress headroom', async () => {
  const { PAD_BLOCK } = await import('../src/vault.js');
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd' });
  const env = JSON.parse(await encodeEnvelope(real, { masterKey: RMK, writerId: 'w', decoy: { vault: decoy, masterKey: DMK } }));
  assert.equal((b64(env.ct).length - 16) % PAD_BLOCK, 0);
});

test('encodeEnvelope without a decoy is unchanged: random filler, no _pad', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const env = JSON.parse(await encodeEnvelope(real, { masterKey: RMK, writerId: 'w' }));
  assert.equal(b64(env.decoy.ct).length, b64(env.ct).length);
  const out = await unlockVault(env, { masterKey: RMK });
  assert.equal(out._pad, undefined);
  assert.equal(JSON.stringify(out.entries).includes('_pad'), false);
});

test('encodeEnvelope decoy: a fresh IV per slot per call', async () => {
  const a = JSON.parse(await encodeEnvelope(createVault(), { masterKey: RMK, writerId: 'w', decoy: { vault: createVault(), masterKey: DMK } }));
  const bEnv = JSON.parse(await encodeEnvelope(createVault(), { masterKey: RMK, writerId: 'w', decoy: { vault: createVault(), masterKey: DMK } }));
  assert.notEqual(a.iv, bEnv.iv);
  assert.notEqual(a.decoy.iv, bEnv.decoy.iv);
  assert.notEqual(a.iv, a.decoy.iv);
});

import { mergeVaults } from '../src/vault.js';

const at = (s) => new Date(s).toISOString();
const ent = (over) => ({ id: 'x', type: 'password', name: 'n', site: 's', account: 'a', counter: 1, length: 20, rules: 'standard', profile: 'v1', totp: null, recoveryCodes: [], notes: '', updatedAt: at('2026-01-01'), ...over });
const vault = (entries, revision = 1, lastWriter = 'A') => ({ entries, settings: { autoLockMinutes: 5 }, revision, lastWriter });

test('mergeVaults: incoming-only id is added', () => {
  const local = vault([ent({ id: '1' })]);
  const incoming = vault([ent({ id: '1' }), ent({ id: '2', name: 'new' })], 2, 'B');
  const { vault: m, summary } = mergeVaults(local, incoming);
  assert.deepEqual(m.entries.map((e) => e.id), ['1', '2']);
  assert.deepEqual(summary.added, ['2']);
});

test('mergeVaults: shared entry — newer updatedAt wins both directions', () => {
  const l1 = mergeVaults(
    vault([ent({ id: '1', name: 'old', updatedAt: at('2026-01-01') })]),
    vault([ent({ id: '1', name: 'NEW', updatedAt: at('2026-02-01') })], 2, 'B'),
  );
  assert.equal(l1.vault.entries[0].name, 'NEW');
  assert.deepEqual(l1.summary.updated, ['1']);
  const l2 = mergeVaults(
    vault([ent({ id: '1', name: 'LOCAL', updatedAt: at('2026-03-01') })]),
    vault([ent({ id: '1', name: 'old', updatedAt: at('2026-02-01') })], 2, 'B'),
  );
  assert.equal(l2.vault.entries[0].name, 'LOCAL');
});

test('mergeVaults: incoming tombstone newer than local live entry -> deleted', () => {
  const { vault: m, summary } = mergeVaults(
    vault([ent({ id: '1', updatedAt: at('2026-01-01') })]),
    vault([{ id: '1', deleted: true, updatedAt: at('2026-02-01') }], 2, 'B'),
  );
  assert.equal(m.entries[0].deleted, true);
  assert.deepEqual(summary.deletedByRemote, ['1']);
});

test('mergeVaults: local tombstone older than incoming live entry -> resurrected', () => {
  const { vault: m, summary } = mergeVaults(
    vault([{ id: '1', deleted: true, updatedAt: at('2026-01-01') }]),
    vault([ent({ id: '1', name: 'back', updatedAt: at('2026-02-01') })], 2, 'B'),
  );
  assert.equal(m.entries[0].name, 'back');
  assert.deepEqual(summary.updated, ['1']);
});

test('mergeVaults: equal entries -> unchanged count, no buckets', () => {
  const e = ent({ id: '1' });
  const { summary } = mergeVaults(vault([e]), vault([{ ...e }], 2, 'B'));
  assert.equal(summary.unchanged, 1);
  assert.deepEqual([summary.added, summary.updated, summary.deletedByRemote, summary.deletedByLocal], [[], [], [], []]);
});

test('mergeVaults: updatedAt tie broken by lastWriter, then local; deterministic both ways', () => {
  const l = vault([ent({ id: '1', name: 'L', updatedAt: at('2026-01-01') })], 1, 'A');
  const r = vault([ent({ id: '1', name: 'R', updatedAt: at('2026-01-01') })], 1, 'B');
  const ab = mergeVaults(l, r).vault.entries[0].name;
  const ba = mergeVaults(r, l).vault.entries[0].name;
  assert.equal(ab, ba, 'commutative outcome');
});

test('mergeVaults: settings follow the higher revision', () => {
  const l = { entries: [], settings: { autoLockMinutes: 5 }, revision: 1, lastWriter: 'A' };
  const r = { entries: [], settings: { autoLockMinutes: 1 }, revision: 9, lastWriter: 'B' };
  assert.equal(mergeVaults(l, r).vault.settings.autoLockMinutes, 1);
  assert.equal(mergeVaults(r, l).vault.settings.autoLockMinutes, 1);
});

test('mergeVaults: order = local order then incoming-only appended', () => {
  const l = vault([ent({ id: '1' }), ent({ id: '2' })]);
  const r = vault([ent({ id: '2' }), ent({ id: '3' }), ent({ id: '1' })], 2, 'B');
  assert.deepEqual(mergeVaults(l, r).vault.entries.map((e) => e.id), ['1', '2', '3']);
});

import { classifyIncoming } from '../src/vault.js';

const envOf = (kcv, revision) => ({ kcv, revision });

test('classifyIncoming: wrong-passphrase when kcv differs', () => {
  assert.equal(
    classifyIncoming(envOf('AAAA', 1), vault([]), envOf('BBBB', 1), vault([])),
    'wrong-passphrase',
  );
});

test('classifyIncoming: same when merge equals local', () => {
  const e = ent({ id: '1' });
  assert.equal(
    classifyIncoming(envOf('K', 1), vault([e]), envOf('K', 1), vault([{ ...e }])),
    'same',
  );
});

test('classifyIncoming: fast-forward when merge equals incoming and revision >=', () => {
  const local = vault([ent({ id: '1' })], 3);
  const incoming = vault([ent({ id: '1' }), ent({ id: '2', name: 'new' })], 5);
  assert.equal(classifyIncoming(envOf('K', 3), local, envOf('K', 5), incoming), 'fast-forward');
});

test('classifyIncoming: diverged when each side has a unique change', () => {
  const local = vault([ent({ id: '1' }), ent({ id: 'L', name: 'local-only' })], 3);
  const incoming = vault([ent({ id: '1' }), ent({ id: 'R', name: 'remote-only' })], 4);
  assert.equal(classifyIncoming(envOf('K', 3), local, envOf('K', 4), incoming), 'diverged');
});
