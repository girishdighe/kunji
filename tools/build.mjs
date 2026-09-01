import { readFileSync, writeFileSync, mkdirSync, cpSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// Explicit dependency order.
// encoding -> webcrypto -> totp -> passkey-store -> qr modules -> derive -> vault -> vault-bridge -> app -> vault-ui.
const JS_ORDER = [
  'src/encoding.js',
  'src/webcrypto.js',
  'src/totp.js',
  'src/passkey-store.js',
  'src/qr.js',
  'src/qr-decode.js',
  'src/qr-transfer.js',
  'src/derive.js',
  'src/vault.js',
  'src/vault-bridge.js',
  'src/app.js',
  'src/vault-ui.js',
];

function stripModuleSyntax(js) {
  return js
    .split('\n')
    .filter((line) => !/^\s*import\s.*from\s.*;?\s*$/.test(line))
    .map((line) => line.replace(/^\s*export\s+(function|const|class|async)\b/, '$1'))
    .map((line) => line.replace(/^\s*export\s*\{[^}]*\};?\s*$/, ''))
    .join('\n');
}

const head = readFileSync('src/head.html', 'utf8');
const tail = readFileSync('src/tail.html', 'utf8');
const css = readFileSync('src/style.css', 'utf8');
const js = JS_ORDER.map((f) => `// ==== ${f} ====\n${stripModuleSyntax(readFileSync(f, 'utf8'))}`).join('\n\n');

const html = head.replace('/*STYLE*/', () => css) + '\n' + tail.replace('/*SCRIPT*/', () => js);

mkdirSync('dist', { recursive: true });
writeFileSync('dist/kunji.html', html);
console.log(`dist/kunji.html written (${html.length} bytes)`);

function buildPwa(shellHtml) {
  const headExtra = readFileSync('tools/pwa/head-extra.html', 'utf8').trim();
  const register = readFileSync('tools/pwa/register.html', 'utf8').trim();

  let idx = shellHtml.replace(
    /(<meta http-equiv="Content-Security-Policy" content="[^"]*?)(">)/,
    (_m, a, b) => `${a}; worker-src 'self'${b}`,
  );
  idx = idx.replace('</head>', `${headExtra}\n</head>`);
  idx = idx.replace('</body>', `</body>\n${register}`);

  mkdirSync('dist/pwa', { recursive: true });
  writeFileSync('dist/pwa/index.html', idx);

  const shellVersion = createHash('sha256').update(readFileSync('dist/pwa/index.html')).digest('hex');
  const assets = ['./', './index.html', './sw.js', './manifest.webmanifest',
    './icon-192.png', './icon-512.png', './icon-512-maskable.png', './apple-touch-icon.png'];
  const sw = readFileSync('tools/pwa/sw.js', 'utf8')
    .replace('__SHELL_VERSION__', shellVersion)
    .replace('__SHELL_ASSETS__', JSON.stringify(assets));
  writeFileSync('dist/pwa/sw.js', sw);

  cpSync('tools/pwa/manifest.webmanifest', 'dist/pwa/manifest.webmanifest');
  execFileSync('node', ['tools/gen-icons.mjs', 'dist/pwa'], { stdio: 'pipe' });
  console.log('dist/pwa/ written');
}

if (!process.argv.includes('--no-pwa')) {
  buildPwa(html);
}
