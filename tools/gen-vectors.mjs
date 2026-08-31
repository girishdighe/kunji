import { writeFileSync, mkdirSync } from 'node:fs';
import { derivePassword, deriveMasterKey, computeKcv, PROFILE } from '../src/derive.js';
import { bytesToHex } from '../src/encoding.js';

// End-to-end cases use a small iteration count for speed. The shipping cost
// (PBKDF2_ITERATIONS) is a separate open decision and does not affect the
// pipeline shape that these vectors lock.
const ITER = 1000;

const cases = [
  { identity: 'alex@example.com', passphrase: 'correct horse battery staple',
    site: 'github.com', account: 'alex', counter: 1, rules: 'standard', length: 20 },
  { identity: 'alex@example.com', passphrase: 'correct horse battery staple',
    site: 'github.com', account: 'alex', counter: 2, rules: 'standard', length: 20 },
  { identity: 'family', passphrase: 'a long enough passphrase here',
    site: 'google.com', account: 'family@example.com', counter: 1, rules: 'max-symbols', length: 32 },
  { identity: 'family', passphrase: 'a long enough passphrase here',
    site: 'router.local', account: 'admin', counter: 1, rules: 'letters-digits', length: 12 },
  { identity: 'x', passphrase: 'y', site: 's', account: 'a', counter: 1, rules: 'standard', length: 8 },
  { identity: 'x', passphrase: 'y', site: 's', account: 'a', counter: 1, rules: 'standard', length: 64 },
];

const out = { profile: PROFILE, iterations: ITER, cases: [] };
for (const c of cases) {
  const mk = await deriveMasterKey(c.passphrase, c.identity, ITER);
  out.cases.push({
    input: c,
    masterKeyHex: bytesToHex(mk),
    kcv: await computeKcv(mk),
    password: await derivePassword({ ...c, iterations: ITER }),
  });
}

mkdirSync('tests/vectors', { recursive: true });
writeFileSync('tests/vectors/v1.json', JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${out.cases.length} vectors`);
