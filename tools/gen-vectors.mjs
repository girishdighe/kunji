import { writeFileSync, mkdirSync } from 'node:fs';
import { derivePassword, deriveMasterKey, computeKcv, PROFILE, PBKDF2_ITERATIONS } from '../src/derive.js';
import { bytesToHex } from '../src/encoding.js';

// The `cases` array uses a small iteration count so the pipeline SHAPE (HKDF
// salt/info, keystream labels, rejection sampling, class order, charsets, KCV)
// can be re-verified in milliseconds. The single `highCost` case below locks the
// actual shipping KDF cost, PBKDF2_ITERATIONS (spec s4.4 step 1). Changing that
// constant makes `vectors.test.mjs` fail until this file is re-run.
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

// One end-to-end case at the real shipping iteration count.
const highInput = {
  identity: 'alex@example.com', passphrase: 'correct horse battery staple',
  site: 'github.com', account: 'alex', counter: 1, rules: 'standard', length: 20,
};
const highMk = await deriveMasterKey(highInput.passphrase, highInput.identity, PBKDF2_ITERATIONS);
out.highCost = {
  iterations: PBKDF2_ITERATIONS,
  input: highInput,
  masterKeyHex: bytesToHex(highMk),
  kcv: await computeKcv(highMk),
  password: await derivePassword({ ...highInput, masterKey: highMk }),
};

mkdirSync('tests/vectors', { recursive: true });
writeFileSync('tests/vectors/v1.json', JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${out.cases.length} vectors + 1 high-cost (${PBKDF2_ITERATIONS} iters)`);
