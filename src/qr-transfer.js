import { utf8, fromUtf8, bytesToBase64, base64ToBytes } from './encoding.js';

const TAG = 'KQR1';

// text -> ['KQR1 <seq> <total> <nonce> <b64 slice>', ...] each <= frameBytes utf8 bytes.
export function splitTransfer(text, { frameBytes }) {
  const b64 = bytesToBase64(utf8(text));
  const nonce = Array.from(randomB64(6)).join('');
  // header without the slice, worst case seq/total width
  const headerLen = (seq, total) => `${TAG} ${seq} ${total} ${nonce} `.length;
  // provisional total from a conservative slice size
  let sliceLen = Math.max(1, frameBytes - headerLen(999, 999));
  let total = Math.ceil(b64.length / sliceLen);
  // recompute with the real digit widths
  sliceLen = Math.max(1, frameBytes - headerLen(total - 1, total));
  total = Math.ceil(b64.length / sliceLen);
  const frames = [];
  for (let seq = 0; seq < total; seq++) {
    frames.push(`${TAG} ${seq} ${total} ${nonce} ${b64.slice(seq * sliceLen, (seq + 1) * sliceLen)}`);
  }
  return frames;
}

// frames -> { text } | { need: number[] } | { error }
export function joinTransfer(frames) {
  const parsed = [];
  for (const f of frames) {
    const m = /^KQR1 (\d+) (\d+) (\S{6}) (.*)$/.exec(f);
    if (m) parsed.push({ seq: +m[1], total: +m[2], nonce: m[3], data: m[4] });
  }
  if (!parsed.length) return { error: 'no valid KQR1 frames' };
  const nonce = parsed[0].nonce;
  const total = parsed[0].total;
  const bySeq = new Map();
  for (const p of parsed) if (p.nonce === nonce && p.total === total) bySeq.set(p.seq, p.data);
  const need = [];
  for (let i = 0; i < total; i++) if (!bySeq.has(i)) need.push(i);
  if (need.length) return { need };
  let b64 = '';
  for (let i = 0; i < total; i++) b64 += bySeq.get(i);
  try {
    return { text: fromUtf8(base64ToBytes(b64)) };
  } catch {
    return { error: 'reassembled payload is not valid base64' };
  }
}

function randomB64(n) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const r = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(r, (x) => A[x & 63]);
}
