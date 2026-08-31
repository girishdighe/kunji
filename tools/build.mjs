import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

// Explicit dependency order. encoding -> webcrypto -> derive -> app.
const JS_ORDER = [
  'src/encoding.js',
  'src/webcrypto.js',
  'src/derive.js',
  'src/app.js',
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
