import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { derivePassword, deriveMasterKey, computeKcv, PROFILE, PBKDF2_ITERATIONS, normaliseInput } from '../src/derive.js';
import { bytesToHex, utf8 as _utf8 } from '../src/encoding.js';
import { pbkdf2Sha512 } from '../src/webcrypto.js';

const vectors = JSON.parse(readFileSync('tests/vectors/v1.json', 'utf8'));

test('committed vectors are for the current profile', () => {
  assert.equal(vectors.profile, PROFILE);
});

test('high-cost vector matches the shipping iteration count', async () => {
  const h = vectors.highCost;
  assert.equal(
    h.iterations, PBKDF2_ITERATIONS,
    'PBKDF2_ITERATIONS changed since the freeze; re-run: node tools/gen-vectors.mjs',
  );
  const mk = await deriveMasterKey(h.input.passphrase, h.input.identity);
  assert.equal(bytesToHex(mk), h.masterKeyHex, 'master key drifted at the shipping cost');
  assert.equal(await computeKcv(mk), h.kcv, 'kcv drifted at the shipping cost');
  assert.equal(
    await derivePassword({ ...h.input, masterKey: mk }),
    h.password,
    'PASSWORD DRIFTED at the shipping iteration count',
  );
});

for (const [i, v] of vectors.cases.entries()) {
  test(`v1 vector ${i} still reproduces (${v.input.site} #${v.input.counter} ${v.input.rules}/${v.input.length})`, async () => {
    const mk = await pbkdf2Sha512(_utf8(v.input.passphrase), _utf8(normaliseInput(v.input.identity)), vectors.iterations, 32);
    assert.equal(bytesToHex(mk), v.masterKeyHex, 'master key drifted');
    assert.equal(await computeKcv(mk), v.kcv, 'kcv drifted');
    assert.equal(
      await derivePassword({ ...v.input, masterKey: mk }),
      v.password,
      'PASSWORD DRIFTED: a v1 profile change would break every existing password',
    );
  });
}
