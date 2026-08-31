import { readFileSync, existsSync } from 'node:fs';
import { readdirSync } from 'node:fs';

const FORBIDDEN = [
  /\bfetch\s*\(/,
  /XMLHttpRequest/,
  /\bWebSocket\b/,
  /sendBeacon/,
  /<script[^>]+\bsrc=/i,
  /<link\b/i,
  /@import\b/,
  /https?:\/\//,
];
// URLs are allowed nowhere in shipped output. The CSP meta uses no URLs.

const targets = [];
for (const f of readdirSync('src')) targets.push(`src/${f}`);
if (existsSync('dist/kunji.html')) targets.push('dist/kunji.html');

let failed = false;
for (const path of targets) {
  const text = readFileSync(path, 'utf8');
  for (const rx of FORBIDDEN) {
    if (rx.test(text)) {
      console.error(`INVARIANT VIOLATION in ${path}: ${rx}`);
      failed = true;
    }
  }
}
if (failed) process.exit(1);
console.log(`invariants ok (${targets.length} files)`);
