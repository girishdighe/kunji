import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { derivePassword, deriveMasterKey, computeKcv, PROFILE } from '../src/derive.js';
import { bytesToHex } from '../src/encoding.js';

const vectors = JSON.parse(readFileSync('tests/vectors/v1.json', 'utf8'));

test('committed vectors are for the current profile', () => {
  assert.equal(vectors.profile, PROFILE);
});

for (const [i, v] of vectors.cases.entries()) {
  test(`v1 vector ${i} still reproduces (${v.input.site} #${v.input.counter} ${v.input.rules}/${v.input.length})`, async () => {
    const mk = await deriveMasterKey(v.input.passphrase, v.input.identity, vectors.iterations);
    assert.equal(bytesToHex(mk), v.masterKeyHex, 'master key drifted');
    assert.equal(await computeKcv(mk), v.kcv, 'kcv drifted');
    assert.equal(
      await derivePassword({ ...v.input, iterations: vectors.iterations }),
      v.password,
      'PASSWORD DRIFTED: a v1 profile change would break every existing password',
    );
  });
}
