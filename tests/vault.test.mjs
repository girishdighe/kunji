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
  createVault, makeEntry, addEntry, updateEntry, removeEntry,
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

test('removeEntry drops by id', () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const id = v.entries[0].id;
  v = removeEntry(v, id);
  assert.equal(v.entries.length, 0);
});

import { encodeEnvelope } from '../src/vault.js';
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS } from '../src/derive.js';
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
