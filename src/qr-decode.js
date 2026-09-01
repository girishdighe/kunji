// QR Code decoder -- image in, byte-mode payload out. Zero dependencies.
// Implements the ISO/IEC 18004:2015 reference decoding algorithm (Annex J);
// clause references appear beside each stage.
//
// Public surface:
//   decodeQr({ data, width, height }) -> Uint8Array | null
//
// `data` is either RGBA (width*height*4 samples) or a single luminance channel
// (width*height samples); the two are told apart by length. The function never
// throws: every failure path, internal or not, returns null.
//
// The build concatenates every src module into a single scope, so all internal
// names here carry a qd/QD_ prefix and stay clear of the encoder's qr/QR_ ones.
// GF(256) and the version geometry tables are deliberately re-implemented here
// rather than imported, because src/qr.js exports only qrMatrix/QR_CAPACITY.

// ---------------------------------------------------------------------------
// GF(256) arithmetic (clause 7.5.2), primitive polynomial x^8+x^4+x^3+x^2+1
// ---------------------------------------------------------------------------

const QD_EXP = new Uint8Array(512);
const QD_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    QD_EXP[i] = x;
    QD_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) QD_EXP[i] = QD_EXP[i - 255];
}

function qdMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return QD_EXP[QD_LOG[a] + QD_LOG[b]];
}

function qdInv(a) {
  return QD_EXP[255 - QD_LOG[a]];
}

// a^e for a != 0.
function qdPow(a, e) {
  if (e === 0) return 1;
  if (a === 0) return 0;
  return QD_EXP[(QD_LOG[a] * e) % 255];
}

function qdPopcount(v) {
  let x = v - ((v >> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
  x = (x + (x >> 4)) & 0x0f0f0f0f;
  return (x * 0x01010101) >> 24;
}

// ---------------------------------------------------------------------------
// Version geometry and error correction block structure (Tables 1, 9, E.1)
// ---------------------------------------------------------------------------

const QD_EC_PER_BLOCK = {
  L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28,
    28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26,
    26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26,
    30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26,
    28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
};

const QD_NUM_BLOCKS = {
  L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7,
    8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14,
    16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21,
    20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25,
    25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
};

// Modules available to data and error correction codewords (clause 7.7.1).
function qdDataModuleCount(version) {
  let n = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    n -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) n -= 36;
  }
  return n;
}

function qdTotalCodewords(version) {
  return Math.floor(qdDataModuleCount(version) / 8);
}

// Alignment pattern centre coordinates (clause 6.3.6, Table E.1).
function qdAlignmentPositions(version) {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const positions = [6];
  for (let pos = version * 4 + 10; positions.length < count; pos -= step) positions.splice(1, 0, pos);
  return positions;
}

// Function-pattern map, byte-identical in shape to the encoder's isFunction
// grid (clauses 6.3.3 - 6.3.6, 7.9, 7.10).
function qdFunctionGrid(version) {
  const size = 17 + 4 * version;
  const fn = [];
  for (let i = 0; i < size; i++) fn.push(new Uint8Array(size));
  const set = (row, col) => {
    if (row < 0 || col < 0 || row >= size || col >= size) return;
    fn[row][col] = 1;
  };

  for (let i = 0; i < size; i++) {
    set(6, i);
    set(i, 6);
  }
  for (const [baseRow, baseCol] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) set(baseRow + dr, baseCol + dc);
    }
  }
  const centres = qdAlignmentPositions(version);
  for (let i = 0; i < centres.length; i++) {
    for (let j = 0; j < centres.length; j++) {
      const skip = (i === 0 && j === 0)
        || (i === 0 && j === centres.length - 1)
        || (i === centres.length - 1 && j === 0);
      if (skip) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) set(centres[i] + dr, centres[j] + dc);
      }
    }
  }
  for (let i = 0; i <= 8; i++) {
    if (i === 6) continue;
    set(i, 8);
    set(8, i);
  }
  for (let i = 0; i < 8; i++) set(8, size - 1 - i);
  for (let i = 0; i < 7; i++) set(size - 1 - i, 8);
  set(size - 8, 8);
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(b, a);
      set(a, b);
    }
  }
  return fn;
}

function qdMaskBit(mask, row, col) {
  switch (mask) {
    case 0: return (row + col) % 2 === 0;
    case 1: return row % 2 === 0;
    case 2: return col % 3 === 0;
    case 3: return (row + col) % 3 === 0;
    case 4: return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5: return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6: return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    default: return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
  }
}

// ---------------------------------------------------------------------------
// E4.1  Luminance and local-mean adaptive thresholding (Annex J.2)
// ---------------------------------------------------------------------------

function qdLuminance(image) {
  const width = image.width | 0;
  const height = image.height | 0;
  const src = image.data;
  if (!src || typeof src.length !== 'number') return null;
  if (width <= 0 || height <= 0) return null;
  if (width > 8192 || height > 8192) return null;
  const pixels = width * height;
  const lum = new Uint8Array(pixels);
  if (src.length >= pixels * 4) {
    for (let i = 0, o = 0; i < pixels; i++, o += 4) {
      lum[i] = (src[o] * 299 + src[o + 1] * 587 + src[o + 2] * 114 + 500) / 1000 | 0;
    }
  } else if (src.length >= pixels) {
    for (let i = 0; i < pixels; i++) lum[i] = src[i];
  } else {
    return null;
  }
  return { lum, width, height };
}

const QD_BLOCK = 8;
// Below this dynamic range a block is assumed to hold a single colour.
const QD_MIN_RANGE = 24;

// Block-based local mean threshold: an 8x8 grid of block means, smoothed over a
// 5x5 block neighbourhood, applied per pixel. Flat blocks fall back to half
// their minimum (so an all-light block stays light) or to their neighbours.
function qdBinarize(lum, width, height) {
  const bw = Math.max(1, Math.ceil(width / QD_BLOCK));
  const bh = Math.max(1, Math.ceil(height / QD_BLOCK));
  const means = new Int32Array(bw * bh);

  for (let by = 0; by < bh; by++) {
    for (let bx = 0; bx < bw; bx++) {
      const x0 = bx * QD_BLOCK;
      const y0 = by * QD_BLOCK;
      const x1 = Math.min(x0 + QD_BLOCK, width);
      const y1 = Math.min(y0 + QD_BLOCK, height);
      let sum = 0;
      let min = 255;
      let max = 0;
      let n = 0;
      for (let y = y0; y < y1; y++) {
        const row = y * width;
        for (let x = x0; x < x1; x++) {
          const v = lum[row + x];
          sum += v;
          n++;
          if (v < min) min = v;
          if (v > max) max = v;
        }
      }
      let mean = n > 0 ? sum / n : 128;
      if (n > 0 && max - min <= QD_MIN_RANGE) {
        mean = min / 2;
        if (by > 0 && bx > 0) {
          const neighbour = (means[(by - 1) * bw + bx]
            + 2 * means[by * bw + bx - 1]
            + means[(by - 1) * bw + bx - 1]) / 4;
          if (min < neighbour) mean = neighbour;
        }
      }
      means[by * bw + bx] = mean;
    }
  }

  const bits = new Uint8Array(width * height);
  for (let by = 0; by < bh; by++) {
    for (let bx = 0; bx < bw; bx++) {
      let sum = 0;
      let n = 0;
      for (let dy = -2; dy <= 2; dy++) {
        const yy = by + dy;
        if (yy < 0 || yy >= bh) continue;
        for (let dx = -2; dx <= 2; dx++) {
          const xx = bx + dx;
          if (xx < 0 || xx >= bw) continue;
          sum += means[yy * bw + xx];
          n++;
        }
      }
      const threshold = sum / n;
      const x0 = bx * QD_BLOCK;
      const y0 = by * QD_BLOCK;
      const x1 = Math.min(x0 + QD_BLOCK, width);
      const y1 = Math.min(y0 + QD_BLOCK, height);
      for (let y = y0; y < y1; y++) {
        const row = y * width;
        for (let x = x0; x < x1; x++) bits[row + x] = lum[row + x] <= threshold ? 1 : 0;
      }
    }
  }
  return bits;
}

// ---------------------------------------------------------------------------
// E4.2  Finder pattern search (Annex J.3)
// ---------------------------------------------------------------------------

// A 1:1:3:1:1 dark/light/dark/light/dark run, +/-50% per module.
function qdIsFinderRun(counts) {
  let total = 0;
  for (let i = 0; i < 5; i++) {
    if (counts[i] === 0) return false;
    total += counts[i];
  }
  if (total < 7) return false;
  const m = total / 7;
  const v = m / 2;
  return Math.abs(m - counts[0]) < v
    && Math.abs(m - counts[1]) < v
    && Math.abs(3 * m - counts[2]) < 3 * v
    && Math.abs(m - counts[3]) < v
    && Math.abs(m - counts[4]) < v;
}

// Continuous centre of the middle run. Pixel k spans [k, k+1), so the centre of
// a run of pixels [a, b) is (a + b) / 2; `end` is the exclusive end of run 4.
function qdCentreFromEnd(counts, end) {
  return (end - counts[4] - counts[3]) - counts[2] / 2;
}

function qdCrossCheckVertical(bits, width, height, startY, centreX, maxCount, originalTotal) {
  const counts = [0, 0, 0, 0, 0];
  const dark = (y) => bits[y * width + centreX] === 1;

  let y = startY;
  while (y >= 0 && dark(y)) { counts[2]++; y--; }
  if (y < 0) return NaN;
  while (y >= 0 && !dark(y) && counts[1] <= maxCount) { counts[1]++; y--; }
  if (y < 0 || counts[1] > maxCount) return NaN;
  while (y >= 0 && dark(y) && counts[0] <= maxCount) { counts[0]++; y--; }
  if (counts[0] > maxCount) return NaN;

  y = startY + 1;
  while (y < height && dark(y)) { counts[2]++; y++; }
  if (y >= height) return NaN;
  while (y < height && !dark(y) && counts[3] < maxCount) { counts[3]++; y++; }
  if (y >= height || counts[3] >= maxCount) return NaN;
  while (y < height && dark(y) && counts[4] < maxCount) { counts[4]++; y++; }
  if (counts[4] >= maxCount) return NaN;

  const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
  if (5 * Math.abs(total - originalTotal) >= 2 * originalTotal) return NaN;
  return qdIsFinderRun(counts) ? qdCentreFromEnd(counts, y) : NaN;
}

function qdCrossCheckHorizontal(bits, width, height, startX, centreY, maxCount, originalTotal) {
  const counts = [0, 0, 0, 0, 0];
  const row = centreY * width;
  const dark = (x) => bits[row + x] === 1;

  let x = startX;
  while (x >= 0 && dark(x)) { counts[2]++; x--; }
  if (x < 0) return NaN;
  while (x >= 0 && !dark(x) && counts[1] <= maxCount) { counts[1]++; x--; }
  if (x < 0 || counts[1] > maxCount) return NaN;
  while (x >= 0 && dark(x) && counts[0] <= maxCount) { counts[0]++; x--; }
  if (counts[0] > maxCount) return NaN;

  x = startX + 1;
  while (x < width && dark(x)) { counts[2]++; x++; }
  if (x >= width) return NaN;
  while (x < width && !dark(x) && counts[3] < maxCount) { counts[3]++; x++; }
  if (x >= width || counts[3] >= maxCount) return NaN;
  while (x < width && dark(x) && counts[4] < maxCount) { counts[4]++; x++; }
  if (counts[4] >= maxCount) return NaN;

  const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
  if (5 * Math.abs(total - originalTotal) >= 2 * originalTotal) return NaN;
  return qdIsFinderRun(counts) ? qdCentreFromEnd(counts, x) : NaN;
}

// Merge a confirmed hit into the candidate list, averaging coincident hits.
function qdRecordCandidate(list, x, y, size) {
  for (const p of list) {
    if (Math.abs(x - p.x) <= p.size && Math.abs(y - p.y) <= p.size) {
      const diff = Math.abs(size - p.size);
      if (diff <= 1 || diff <= p.size) {
        const n = p.count + 1;
        p.x = (p.x * p.count + x) / n;
        p.y = (p.y * p.count + y) / n;
        p.size = (p.size * p.count + size) / n;
        p.count = n;
        return;
      }
    }
  }
  list.push({ x, y, size, count: 1 });
}

function qdConfirmCandidate(bits, width, height, counts, y, xEnd, list) {
  const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
  const cx = qdCentreFromEnd(counts, xEnd);
  const cxi = Math.floor(cx);
  if (cxi < 0 || cxi >= width) return;
  const cy = qdCrossCheckVertical(bits, width, height, y, cxi, counts[2], total);
  if (!(cy >= 0)) return;
  const cyi = Math.floor(cy);
  if (cyi < 0 || cyi >= height) return;
  const cx2 = qdCrossCheckHorizontal(bits, width, height, cxi, cyi, counts[2], total);
  if (!(cx2 >= 0)) return;
  qdRecordCandidate(list, cx2, cy, total / 7);
}

function qdFindFinders(bits, width, height) {
  const list = [];
  const counts = [0, 0, 0, 0, 0];
  for (let y = 0; y < height; y++) {
    counts[0] = counts[1] = counts[2] = counts[3] = counts[4] = 0;
    let state = 0;
    const row = y * width;
    for (let x = 0; x < width; x++) {
      if (bits[row + x] === 1) {
        if (state & 1) state++;
        counts[state]++;
      } else if ((state & 1) === 0) {
        if (state === 4) {
          if (qdIsFinderRun(counts)) qdConfirmCandidate(bits, width, height, counts, y, x, list);
          counts[0] = counts[2];
          counts[1] = counts[3];
          counts[2] = counts[4];
          counts[3] = 1;
          counts[4] = 0;
          state = 3;
        } else {
          state++;
          counts[state]++;
        }
      } else {
        counts[state]++;
      }
    }
    if (state === 4 && qdIsFinderRun(counts)) {
      qdConfirmCandidate(bits, width, height, counts, y, width, list);
    }
  }
  return list;
}

// ---------------------------------------------------------------------------
// E4.3  Symbol geometry: finder ordering, module size, version estimate
// ---------------------------------------------------------------------------

function qdDistance(a, b) {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

// Identify top-left (the right-angle vertex, opposite the longest side) and
// then top-right / bottom-left by the sign of the cross product. Image y grows
// downward, so an unmirrored symbol has cross(TR-TL, BL-TL) > 0; rotations
// preserve that sign, which is what makes 90/180/270 fall out for free.
function qdGeometry(p, q, r) {
  const dpq = qdDistance(p, q);
  const dpr = qdDistance(p, r);
  const dqr = qdDistance(q, r);
  let tl;
  let a;
  let b;
  if (dqr >= dpq && dqr >= dpr) { tl = p; a = q; b = r; }
  else if (dpr >= dpq && dpr >= dqr) { tl = q; a = p; b = r; }
  else { tl = r; a = p; b = q; }

  const cross = (a.x - tl.x) * (b.y - tl.y) - (a.y - tl.y) * (b.x - tl.x);
  if (cross === 0) return null;
  const tr = cross > 0 ? a : b;
  const bl = cross > 0 ? b : a;

  const moduleSize = (p.size + q.size + r.size) / 3;
  if (!(moduleSize > 0.9)) return null;

  const dTR = qdDistance(tl, tr);
  const dBL = qdDistance(tl, bl);
  const longer = Math.max(dTR, dBL);
  if (longer <= 0) return null;
  // The two arms of the L must be about equal for a square symbol.
  if (Math.abs(dTR - dBL) > 0.4 * longer) return null;

  let dimension = Math.round((dTR + dBL) / 2 / moduleSize) + 7;
  dimension = Math.round((dimension - 1) / 4) * 4 + 1;
  if (dimension < 21 || dimension > 177) return null;

  return { tl, tr, bl, moduleSize, dimension };
}

// Enumerate plausible finder triples, best first. Normally there are exactly
// three candidates and this yields one triple.
function qdTriples(candidates) {
  const sorted = candidates.slice().sort((x, y) => y.count - x.count).slice(0, 8);
  if (sorted.length < 3) return [];
  const out = [];
  for (let i = 0; i < sorted.length; i++) {
    for (let j = i + 1; j < sorted.length; j++) {
      for (let k = j + 1; k < sorted.length; k++) {
        const t = [sorted[i], sorted[j], sorted[k]];
        const mean = (t[0].size + t[1].size + t[2].size) / 3;
        let spread = 0;
        for (const c of t) spread += Math.abs(c.size - mean);
        out.push({ t, score: spread / Math.max(mean, 1e-6) - (t[0].count + t[1].count + t[2].count) / 1000 });
      }
    }
  }
  out.sort((x, y) => x.score - y.score);
  return out.slice(0, 16).map((e) => e.t);
}

// ---------------------------------------------------------------------------
// Alignment pattern search (clause 6.3.6): a 1:1:1:1:1 dark/light/dark/light/
// dark cross. The outer two runs may bleed into adjacent dark data modules, so
// only the inner three runs are size-checked; the centre is measured from the
// end of run 3, which is unaffected by run 4 being long.
// ---------------------------------------------------------------------------

function qdIsAlignRun(counts, ms) {
  const v = ms / 2;
  if (counts[0] * 2 < ms || counts[4] * 2 < ms) return false;
  return Math.abs(counts[1] - ms) < v && Math.abs(counts[2] - ms) < v && Math.abs(counts[3] - ms) < v;
}

function qdAlignVertical(bits, width, height, centreX, startY, ms) {
  const counts = [0, 0, 0, 0, 0];
  const cap = Math.max(2, Math.ceil(ms * 2));
  const dark = (y) => bits[y * width + centreX] === 1;
  if (!dark(startY)) return NaN;

  let y = startY;
  while (y >= 0 && dark(y)) { counts[2]++; y--; }
  while (y >= 0 && !dark(y) && counts[1] < cap) { counts[1]++; y--; }
  while (y >= 0 && dark(y) && counts[0] < cap) { counts[0]++; y--; }

  y = startY + 1;
  while (y < height && dark(y)) { counts[2]++; y++; }
  while (y < height && !dark(y) && counts[3] < cap) { counts[3]++; y++; }
  while (y < height && dark(y) && counts[4] < cap) { counts[4]++; y++; }

  return qdIsAlignRun(counts, ms) ? qdCentreFromEnd(counts, y) : NaN;
}

function qdFindAlignment(bits, width, height, estX, estY, ms) {
  const allowance = Math.max(3, Math.round(4 * ms));
  const left = Math.max(0, Math.floor(estX) - allowance);
  const right = Math.min(width, Math.floor(estX) + allowance + 1);
  const top = Math.max(0, Math.floor(estY) - allowance);
  const bottom = Math.min(height, Math.floor(estY) + allowance + 1);
  if (right - left < 5 || bottom - top < 5) return null;

  let best = null;
  const counts = [0, 0, 0, 0, 0];
  for (let y = top; y < bottom; y++) {
    counts[0] = counts[1] = counts[2] = counts[3] = counts[4] = 0;
    let state = 0;
    const row = y * width;
    let x = left;
    while (x < right && bits[row + x] !== 1) x++; // burn the leading light run
    for (; x < right; x++) {
      if (bits[row + x] === 1) {
        if (state & 1) state++;
        counts[state]++;
      } else if ((state & 1) === 0) {
        if (state === 4) {
          if (qdIsAlignRun(counts, ms)) {
            const cx = qdCentreFromEnd(counts, x);
            const cxi = Math.floor(cx);
            if (cxi >= 0 && cxi < width) {
              const cy = qdAlignVertical(bits, width, height, cxi, y, ms);
              if (cy >= 0) {
                const d = Math.hypot(cx - estX, cy - estY);
                if (!best || d < best.d) best = { x: cx, y: cy, d };
              }
            }
          }
          counts[0] = counts[2];
          counts[1] = counts[3];
          counts[2] = counts[4];
          counts[3] = 1;
          counts[4] = 0;
          state = 3;
        } else {
          state++;
          counts[state]++;
        }
      } else {
        counts[state]++;
      }
    }
  }
  if (!best || best.d > 2.5 * ms) return null;
  return { x: best.x, y: best.y };
}

// ---------------------------------------------------------------------------
// E4.4  Perspective transform and grid sampling (Annex J.5)
// ---------------------------------------------------------------------------

// Solve the 8 unknowns of the homography mapping four module-space points to
// four image-space points (h33 fixed at 1), by Gaussian elimination.
function qdHomography(src, dst) {
  const rows = [];
  for (let i = 0; i < 4; i++) {
    const u = src[i].x;
    const v = src[i].y;
    const x = dst[i].x;
    const y = dst[i].y;
    rows.push([u, v, 1, 0, 0, 0, -u * x, -v * x, x]);
    rows.push([0, 0, 0, u, v, 1, -u * y, -v * y, y]);
  }
  const n = 8;
  for (let col = 0; col < n; col++) {
    let pivot = col;
    for (let r = col + 1; r < n; r++) {
      if (Math.abs(rows[r][col]) > Math.abs(rows[pivot][col])) pivot = r;
    }
    if (Math.abs(rows[pivot][col]) < 1e-9) return null;
    if (pivot !== col) {
      const t = rows[pivot];
      rows[pivot] = rows[col];
      rows[col] = t;
    }
    const inv = 1 / rows[col][col];
    for (let r = col + 1; r < n; r++) {
      const f = rows[r][col] * inv;
      if (f === 0) continue;
      for (let c = col; c <= n; c++) rows[r][c] -= f * rows[col][c];
    }
  }
  const h = new Float64Array(9);
  for (let r = n - 1; r >= 0; r--) {
    let s = rows[r][n];
    for (let c = r + 1; c < n; c++) s -= rows[r][c] * h[c];
    h[r] = s / rows[r][r];
    if (!Number.isFinite(h[r])) return null;
  }
  h[8] = 1;
  return h;
}

const QD_SAMPLE_OFFSETS = [[0, 0], [-1, 0], [1, 0], [0, -1], [0, 1]];

function qdSampleModule(bits, width, height, x, y, d) {
  let dark = 0;
  let n = 0;
  for (let i = 0; i < QD_SAMPLE_OFFSETS.length; i++) {
    const px = Math.floor(x + QD_SAMPLE_OFFSETS[i][0] * d);
    const py = Math.floor(y + QD_SAMPLE_OFFSETS[i][1] * d);
    if (px < 0 || py < 0 || px >= width || py >= height) continue;
    n++;
    if (bits[py * width + px] === 1) dark++;
  }
  if (n === 0) return false;
  return dark * 2 > n;
}

// Module (row, col) covers [col, col+1) x [row, row+1) in module space, so its
// centre is (col + 0.5, row + 0.5); the finder centres are module (3,3) etc.
function qdBuildMatrix(bits, width, height, geom, dimension, alignPoint) {
  const src = [
    { x: 3.5, y: 3.5 },
    { x: dimension - 3.5, y: 3.5 },
    { x: 3.5, y: dimension - 3.5 },
    alignPoint ? { x: dimension - 6.5, y: dimension - 6.5 } : { x: dimension - 3.5, y: dimension - 3.5 },
  ];
  const corner = {
    x: geom.tr.x + geom.bl.x - geom.tl.x,
    y: geom.tr.y + geom.bl.y - geom.tl.y,
  };
  const dst = [geom.tl, geom.tr, geom.bl, alignPoint || corner];
  const h = qdHomography(src, dst);
  if (!h) return null;

  const d = Math.max(1, Math.floor(geom.moduleSize / 4));
  const matrix = [];
  for (let row = 0; row < dimension; row++) {
    const line = new Array(dimension);
    for (let col = 0; col < dimension; col++) {
      const u = col + 0.5;
      const v = row + 0.5;
      const w = h[6] * u + h[7] * v + 1;
      if (!w) return null;
      line[col] = qdSampleModule(
        bits, width, height,
        (h[0] * u + h[1] * v + h[2]) / w,
        (h[3] * u + h[4] * v + h[5]) / w,
        d,
      );
    }
    matrix.push(line);
  }
  return matrix;
}

const QD_FINDER_SHAPE = [
  [1, 1, 1, 1, 1, 1, 1],
  [1, 0, 0, 0, 0, 0, 1],
  [1, 0, 1, 1, 1, 0, 1],
  [1, 0, 1, 1, 1, 0, 1],
  [1, 0, 1, 1, 1, 0, 1],
  [1, 0, 0, 0, 0, 0, 1],
  [1, 1, 1, 1, 1, 1, 1],
];

// Cheap structural gate: the three finders and both timing patterns must be
// mostly right before the format/RS machinery is worth running.
function qdValidateMatrix(m) {
  const size = m.length;
  let bad = 0;
  for (const [baseRow, baseCol] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        if ((m[baseRow + r][baseCol + c] ? 1 : 0) !== QD_FINDER_SHAPE[r][c]) bad++;
      }
    }
  }
  if (bad > 6) return false;
  let timingBad = 0;
  let timingTotal = 0;
  for (let i = 8; i < size - 8; i++) {
    const expected = i % 2 === 0;
    timingTotal += 2;
    if (m[6][i] !== expected) timingBad++;
    if (m[i][6] !== expected) timingBad++;
  }
  return timingTotal === 0 || timingBad * 5 <= timingTotal;
}

function qdRotate(m) {
  const n = m.length;
  const out = [];
  for (let r = 0; r < n; r++) {
    const line = new Array(n);
    for (let c = 0; c < n; c++) line[c] = m[n - 1 - c][r];
    out.push(line);
  }
  return out;
}

// ---------------------------------------------------------------------------
// E4.5  Format and version information (clauses 7.9, 7.10)
// ---------------------------------------------------------------------------

function qdBchRemainder(value, generator, degree) {
  let rem = value;
  for (let i = degree - 1; i >= 0; i--) {
    if (rem >>> (degree + i) & 1) rem ^= generator << i;
  }
  return rem;
}

const QD_FORMAT_CODES = (() => {
  const codes = new Int32Array(32);
  for (let d = 0; d < 32; d++) {
    const rem = qdBchRemainder(d << 10, 0b10100110111, 10);
    codes[d] = (((d << 10) | rem) ^ 0x5412) & 0x7fff;
  }
  return codes;
})();

const QD_VERSION_CODES = (() => {
  const codes = new Int32Array(34);
  for (let v = 7; v <= 40; v++) {
    const rem = qdBchRemainder(v << 12, 0b1111100100101, 12);
    codes[v - 7] = ((v << 12) | rem) & 0x3ffff;
  }
  return codes;
})();

// Indexed by the 2-bit ECC indicator: 01=L, 00=M, 11=Q, 10=H.
const QD_ECC_FROM_BITS = ['M', 'L', 'H', 'Q'];

function qdReadFormat(m) {
  const size = m.length;
  const bit = (r, c) => (m[r][c] ? 1 : 0);

  let copy1 = 0;
  for (let i = 0; i <= 5; i++) copy1 |= bit(i, 8) << i;
  copy1 |= bit(7, 8) << 6;
  copy1 |= bit(8, 8) << 7;
  copy1 |= bit(8, 7) << 8;
  for (let i = 9; i < 15; i++) copy1 |= bit(8, 14 - i) << i;

  let copy2 = 0;
  for (let i = 0; i < 8; i++) copy2 |= bit(8, size - 1 - i) << i;
  for (let i = 8; i < 15; i++) copy2 |= bit(size - 15 + i, 8) << i;

  let best = -1;
  let bestDist = 4;
  for (const raw of [copy1, copy2]) {
    for (let d = 0; d < 32; d++) {
      const dist = qdPopcount(raw ^ QD_FORMAT_CODES[d]);
      if (dist < bestDist) {
        bestDist = dist;
        best = d;
      }
    }
  }
  if (best < 0) return null;
  return { ecc: QD_ECC_FROM_BITS[(best >> 3) & 3], mask: best & 7 };
}

function qdReadVersionInfo(m) {
  const size = m.length;
  if (size < 45) return null;
  let copy1 = 0;
  let copy2 = 0;
  for (let i = 0; i < 18; i++) {
    const a = size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    if (m[b][a]) copy1 |= 1 << i;
    if (m[a][b]) copy2 |= 1 << i;
  }
  let best = null;
  let bestDist = 4;
  for (const raw of [copy1, copy2]) {
    for (let v = 7; v <= 40; v++) {
      const dist = qdPopcount(raw ^ QD_VERSION_CODES[v - 7]);
      if (dist < bestDist) {
        bestDist = dist;
        best = v;
      }
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// E4.6  Unmasking and symbol character reading (clause 7.7.3)
// ---------------------------------------------------------------------------

function qdReadCodewords(m, fn, mask, version) {
  const size = m.length;
  const total = qdTotalCodewords(version);
  const out = new Uint8Array(total);
  const totalBits = total * 8;
  let bit = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const col = right - j;
        const upward = ((right + 1) & 2) === 0;
        const row = upward ? size - 1 - vert : vert;
        if (!fn[row][col] && bit < totalBits) {
          let dark = m[row][col];
          if (qdMaskBit(mask, row, col)) dark = !dark;
          if (dark) out[bit >>> 3] |= 0x80 >>> (bit & 7);
          bit++;
        }
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// E4.7  Reed-Solomon decoding (clauses 7.5.3, 7.6)
// ---------------------------------------------------------------------------

function qdSyndromes(msg, ecLen) {
  const synd = new Uint8Array(ecLen);
  let any = false;
  for (let j = 0; j < ecLen; j++) {
    const root = QD_EXP[j];
    let s = 0;
    for (let i = 0; i < msg.length; i++) s = qdMul(s, root) ^ msg[i];
    synd[j] = s;
    if (s !== 0) any = true;
  }
  return any ? synd : null;
}

// In-place correction of one block. The generator roots are a^0..a^(ecLen-1),
// matching the encoder. Returns false when the block cannot be corrected --
// too many errors, an inconsistent locator, or residual syndromes.
function qdRsCorrect(msg, ecLen) {
  const synd = qdSyndromes(msg, ecLen);
  if (!synd) return true;
  const n = msg.length;
  const t = ecLen >> 1;

  // Berlekamp-Massey. lambda/prev hold coefficients by ascending degree.
  let lambda = [1];
  let prev = [1];
  let L = 0;
  let shift = 1;
  let b = 1;
  for (let k = 0; k < ecLen; k++) {
    let delta = synd[k];
    for (let i = 1; i <= L; i++) delta ^= qdMul(lambda[i] || 0, synd[k - i]);
    if (delta === 0) {
      shift++;
      continue;
    }
    const saved = lambda.slice();
    const coef = qdMul(delta, qdInv(b));
    for (let i = 0; i < prev.length; i++) {
      const idx = i + shift;
      while (lambda.length <= idx) lambda.push(0);
      lambda[idx] ^= qdMul(coef, prev[i]);
    }
    if (2 * L <= k) {
      L = k + 1 - L;
      prev = saved;
      b = delta;
      shift = 1;
    } else {
      shift++;
    }
  }
  while (lambda.length > 1 && lambda[lambda.length - 1] === 0) lambda.pop();
  const errors = lambda.length - 1;
  if (errors < 1 || errors > t) return false;

  // Chien search: lambda(a^-d) == 0 marks an error at codeword index n-1-d.
  const positions = [];
  for (let i = 0; i < n; i++) {
    const deg = (n - 1 - i) % 255;
    const xInv = QD_EXP[(255 - deg) % 255];
    let val = 0;
    for (let p = lambda.length - 1; p >= 0; p--) val = qdMul(val, xInv) ^ lambda[p];
    if (val === 0) positions.push(i);
  }
  if (positions.length !== errors) return false;

  // Forney: omega = S(x)*lambda(x) mod x^ecLen, magnitude X*omega(X^-1)/lambda'(X^-1).
  const omega = new Uint8Array(ecLen);
  for (let i = 0; i < ecLen; i++) {
    let s = 0;
    for (let j = 0; j <= i && j < lambda.length; j++) s ^= qdMul(synd[i - j], lambda[j]);
    omega[i] = s;
  }
  for (const i of positions) {
    const deg = (n - 1 - i) % 255;
    const x = QD_EXP[deg];
    const xInv = QD_EXP[(255 - deg) % 255];
    let om = 0;
    for (let p = omega.length - 1; p >= 0; p--) om = qdMul(om, xInv) ^ omega[p];
    let der = 0;
    for (let p = 1; p < lambda.length; p += 2) der ^= qdMul(lambda[p], qdPow(xInv, p - 1));
    if (der === 0) return false;
    msg[i] ^= qdMul(x, qdMul(om, qdInv(der)));
  }
  return qdSyndromes(msg, ecLen) === null;
}

// Reverse the encoder's interleave (clause 7.6), correct every block, and
// concatenate the corrected data codewords in block order.
function qdDeinterleave(codewords, version, ecc) {
  const numBlocks = QD_NUM_BLOCKS[ecc][version];
  const ecLen = QD_EC_PER_BLOCK[ecc][version];
  const raw = qdTotalCodewords(version);
  const shortLen = Math.floor(raw / numBlocks) - ecLen;
  const shortCount = numBlocks - (raw % numBlocks);
  if (shortLen < 1) return null;

  const lengths = [];
  const blocks = [];
  let dataTotal = 0;
  for (let b = 0; b < numBlocks; b++) {
    const len = shortLen + (b < shortCount ? 0 : 1);
    lengths.push(len);
    dataTotal += len;
    blocks.push(new Uint8Array(len + ecLen));
  }
  if (dataTotal + numBlocks * ecLen !== raw) return null;

  let k = 0;
  for (let i = 0; i <= shortLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < lengths[b]) blocks[b][i] = codewords[k++];
    }
  }
  for (let i = 0; i < ecLen; i++) {
    for (let b = 0; b < numBlocks; b++) blocks[b][lengths[b] + i] = codewords[k++];
  }

  const out = new Uint8Array(dataTotal);
  let o = 0;
  for (let b = 0; b < numBlocks; b++) {
    if (!qdRsCorrect(blocks[b], ecLen)) return null;
    for (let i = 0; i < lengths[b]; i++) out[o++] = blocks[b][i];
  }
  return out;
}

// ---------------------------------------------------------------------------
// E4.8  Bit stream parsing (clauses 7.4.1, 7.4.3, 7.4.5)
// ---------------------------------------------------------------------------

function qdParsePayload(data, version) {
  const totalBits = data.length * 8;
  let pos = 0;
  const read = (count) => {
    if (pos + count > totalBits) return -1;
    let value = 0;
    for (let i = 0; i < count; i++, pos++) {
      value = (value << 1) | ((data[pos >>> 3] >>> (7 - (pos & 7))) & 1);
    }
    return value;
  };

  const mode = read(4);
  if (mode !== 0b0100) return null; // byte mode only; ECI and the rest are out
  const count = read(version <= 9 ? 8 : 16);
  if (count < 0) return null;
  if (pos + count * 8 > totalBits) return null;
  const out = new Uint8Array(count);
  for (let i = 0; i < count; i++) out[i] = read(8);
  return out;
}

// ---------------------------------------------------------------------------
// Matrix -> payload
// ---------------------------------------------------------------------------

function qdDecodeMatrix(m) {
  const size = m.length;
  if (size < 21 || size > 177 || (size - 21) % 4 !== 0) return null;
  const version = (size - 17) / 4;
  if (size >= 45) {
    const declared = qdReadVersionInfo(m);
    if (declared !== null && declared !== version) return null;
  }
  const format = qdReadFormat(m);
  if (!format) return null;
  const codewords = qdReadCodewords(m, qdFunctionGrid(version), format.mask, version);
  const data = qdDeinterleave(codewords, version, format.ecc);
  if (!data) return null;
  return qdParsePayload(data, version);
}

function qdDecodeVariants(m) {
  let variant = m;
  for (let i = 0; i < 4; i++) {
    if (i > 0) variant = qdRotate(variant);
    if (!qdValidateMatrix(variant)) continue;
    const payload = qdDecodeMatrix(variant);
    if (payload) return payload;
  }
  return null;
}

function qdAttempt(bits, width, height, triple) {
  const geom = qdGeometry(triple[0], triple[1], triple[2]);
  if (!geom) return null;

  const dimensions = [geom.dimension];
  for (let idx = 0; idx < dimensions.length && idx < 5; idx++) {
    const dimension = dimensions[idx];
    if (dimension < 21 || dimension > 177) continue;

    // The three-point (affine) sampling first, then a four-point homography
    // anchored on the bottom-right alignment pattern when one can be found.
    const plain = qdBuildMatrix(bits, width, height, geom, dimension, null);
    if (plain) {
      if (qdValidateMatrix(plain)) {
        const payload = qdDecodeMatrix(plain);
        if (payload) return payload;
      }
      // Prefer a version read out of the symbol over the geometric estimate.
      const declared = dimension >= 45 ? qdReadVersionInfo(plain) : null;
      if (declared !== null && 17 + 4 * declared !== dimension
        && !dimensions.includes(17 + 4 * declared)) {
        dimensions.push(17 + 4 * declared);
      }
    }

    if (dimension > 21) {
      const scale = 1 - 3 / (dimension - 7);
      const cornerX = geom.tr.x + geom.bl.x - geom.tl.x;
      const cornerY = geom.tr.y + geom.bl.y - geom.tl.y;
      const align = qdFindAlignment(
        bits, width, height,
        geom.tl.x + scale * (cornerX - geom.tl.x),
        geom.tl.y + scale * (cornerY - geom.tl.y),
        geom.moduleSize,
      );
      if (align) {
        const warped = qdBuildMatrix(bits, width, height, geom, dimension, align);
        if (warped) {
          const payload = qdDecodeVariants(warped);
          if (payload) return payload;
        }
      }
    }

    if (plain) {
      const payload = qdDecodeVariants(plain);
      if (payload) return payload;
    }

    if (idx === 0) {
      if (dimension - 4 >= 21) dimensions.push(dimension - 4);
      if (dimension + 4 <= 177) dimensions.push(dimension + 4);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export function decodeQr(image) {
  try {
    if (!image || typeof image !== 'object') return null;
    const source = qdLuminance(image);
    if (!source) return null;
    const bits = qdBinarize(source.lum, source.width, source.height);
    const candidates = qdFindFinders(bits, source.width, source.height);
    if (candidates.length < 3) return null;
    for (const triple of qdTriples(candidates)) {
      const payload = qdAttempt(bits, source.width, source.height, triple);
      if (payload) return payload;
    }
    return null;
  } catch (_) {
    return null;
  }
}
