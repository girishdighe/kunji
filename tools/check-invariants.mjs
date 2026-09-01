import { readFileSync, existsSync, readdirSync } from 'node:fs';

// Strict pass: shipped single-file output and every source file.
const STRICT = [
  /\bfetch\s*\(/,
  /XMLHttpRequest/,
  /\bWebSocket\b/,
  /sendBeacon/,
  /<script[^>]+\bsrc=/i,
  /<link\b/i,
  /@import\b/,
  /https?:\/\//,
];

const strictTargets = [];
for (const f of readdirSync('src')) strictTargets.push(`src/${f}`);
if (existsSync('dist/kunji.html')) strictTargets.push('dist/kunji.html');

let failed = false;
for (const path of strictTargets) {
  const text = readFileSync(path, 'utf8');
  for (const rx of STRICT) {
    if (rx.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: ${rx}`); failed = true; }
  }
}

// Relaxed pass: the PWA build. Still no external origins, still no connect-src.
// The manifest <link>, the same-origin serviceWorker.register, and (only in
// sw.js) caches/fetch are allowed.
if (existsSync('dist/pwa')) {
  for (const f of readdirSync('dist/pwa')) {
    if (!/\.(html|js|webmanifest)$/.test(f)) continue; // skip PNGs
    const path = `dist/pwa/${f}`;
    const text = readFileSync(path, 'utf8');
    if (/https?:\/\//.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: external URL`); failed = true; }
    if (/connect-src/.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: connect-src`); failed = true; }
    if (f !== 'sw.js') {
      if (/\bfetch\s*\(/.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: fetch() outside sw.js`); failed = true; }
      if (/XMLHttpRequest|\bWebSocket\b|sendBeacon/.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: network API`); failed = true; }
    }
  }
}

if (failed) process.exit(1);
const count = strictTargets.length + (existsSync('dist/pwa') ? readdirSync('dist/pwa').filter((f) => /\.(html|js|webmanifest)$/.test(f)).length : 0);
console.log(`invariants ok (${count} files)`);
