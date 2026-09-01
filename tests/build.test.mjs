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
