export function estimateEntropyBits(length, charsetSize) {
  if (length <= 0) return 0;
  return Math.floor(length * Math.log2(charsetSize));
}

export function groupInFours(str) {
  return str.replace(/(.{4})/g, '$1 ').trim();
}

// DOM wiring is added in Task 14. Guard so this module is import-safe in Node.
if (typeof document !== 'undefined') {
  // initUI() is defined in Task 14 and called here.
}
