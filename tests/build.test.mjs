import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

test('build produces dist/kunji.html with no module keywords or network refs', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');

  assert.ok(html.startsWith('<!doctype html>'), 'must start with doctype');
  assert.ok(html.includes('<style>'), 'css must be inlined');
  assert.ok(html.includes('<script>'), 'js must be inlined');
  assert.doesNotMatch(html, /^\s*import\s/m, 'no bare import statements');
  assert.doesNotMatch(html, /^\s*export\s/m, 'no bare export statements');
  assert.doesNotMatch(html, /\bfetch\s*\(/, 'no fetch');
  assert.doesNotMatch(html, /XMLHttpRequest|WebSocket|sendBeacon/, 'no network APIs');
  assert.doesNotMatch(html, /https?:\/\//, 'no absolute URLs');
  assert.doesNotMatch(html, /\/STYLE\/|\/SCRIPT\//, 'placeholders replaced');
});

test('check-invariants exits 0 on clean tree', () => {
  execFileSync('node', ['tools/check-invariants.mjs'], { stdio: 'pipe' });
});

test('built html inlines the vault modules', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/vault.js ===='), 'vault.js concatenated');
  assert.ok(html.includes('==== src/vault-ui.js ===='), 'vault-ui.js concatenated');
  assert.ok(html.indexOf('src/vault.js') < html.indexOf('src/app.js'), 'vault.js before app.js');
  assert.ok(html.indexOf('src/app.js') < html.indexOf('src/vault-ui.js'), 'vault-ui.js last');
});

test('built html inlines vault-bridge, ordered after vault.js and before app.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/vault-bridge.js ===='), 'vault-bridge.js concatenated');
  assert.ok(html.indexOf('src/vault.js') < html.indexOf('src/vault-bridge.js'), 'after vault.js');
  assert.ok(html.indexOf('src/vault-bridge.js') < html.indexOf('src/app.js'), 'before app.js');
});

test('built html inlines src/totp.js after webcrypto.js and before vault.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/totp.js ===='), 'totp.js concatenated');
  assert.ok(html.indexOf('src/webcrypto.js') < html.indexOf('src/totp.js'));
  assert.ok(html.indexOf('src/totp.js') < html.indexOf('src/vault.js'));
});

test('built html inlines the qr modules after encoding.js and before vault.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  for (const m of ['src/qr.js', 'src/qr-transfer.js', 'src/qr-decode.js']) {
    assert.ok(html.includes(`==== ${m} ====`), `${m} concatenated`);
    assert.ok(html.indexOf('src/encoding.js') < html.indexOf(m), `${m} after encoding.js`);
    assert.ok(html.indexOf(m) < html.indexOf('src/vault.js'), `${m} before vault.js`);
  }
});

test('built html inlines src/passkey-store.js before vault.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/passkey-store.js ===='));
  assert.ok(html.indexOf('src/passkey-store.js') < html.indexOf('src/vault.js'));
});
