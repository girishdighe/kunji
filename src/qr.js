// QR Code encoder -- byte mode only, zero dependencies.
// Implements ISO/IEC 18004:2015. Clause references appear beside each stage.
//
// Public surface:
//   qrMatrix(bytes, { ecc })  -> boolean[][]  (true = dark, no quiet zone)
//   QR_CAPACITY[version][ecc] -> max byte-mode data bytes

const QR_ECC_LEVELS = ['L', 'M', 'Q', 'H'];

// ---------------------------------------------------------------------------
// E1.1  GF(256) arithmetic (clause 7.5.2), primitive polynomial x^8+x^4+x^3+x^2+1
// ---------------------------------------------------------------------------

const QR_GF_EXP = new Uint8Array(512);
const QR_GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    QR_GF_EXP[i] = x;
    QR_GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  // Duplicate so gfMul can index log(a)+log(b) (max 508) without a modulo.
  for (let i = 255; i < 512; i++) QR_GF_EXP[i] = QR_GF_EXP[i - 255];
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return QR_GF_EXP[QR_GF_LOG[a] + QR_GF_LOG[b]];
}

// ---------------------------------------------------------------------------
// E1.2  Reed-Solomon (clause 7.5.2)
// ---------------------------------------------------------------------------

// Generator polynomial (x - a^0)(x - a^1)...(x - a^(degree-1)).
// Coefficients are stored highest power first, omitting the leading 1.
function rsGenerator(degree) {
  const coefs = new Uint8Array(degree);
  coefs[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      coefs[j] = gfMul(coefs[j], root);
      if (j + 1 < degree) coefs[j] ^= coefs[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return coefs;
}

// Error correction codewords for `data`: the remainder of data*x^ecLen / g(x).
function rsEncode(data, ecLen) {
  const gen = rsGenerator(ecLen);
  const rem = new Uint8Array(ecLen);
  for (let k = 0; k < data.length; k++) {
    const factor = data[k] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecLen - 1] = 0;
    for (let i = 0; i < ecLen; i++) rem[i] ^= gfMul(gen[i], factor);
  }
  return rem;
}

// ---------------------------------------------------------------------------
// Version geometry and the error correction block structure (Tables 1, 9, E.1)
// ---------------------------------------------------------------------------

// Error correction codewords per block, indexed [ecc][version]; index 0 unused.
const QR_EC_PER_BLOCK = {
  L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28,
    28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26,
    26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26,
    30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26,
    28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
};

// Number of error correction blocks, indexed [ecc][version]; index 0 unused.
const QR_NUM_BLOCKS = {
  L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7,
    8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14,
    16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21,
    20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25,
    25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
};

// Total number of modules available for data and error correction codewords,
// i.e. every module except function patterns and the format/version areas
// (clause 7.7.1).
function qrDataModuleCount(version) {
  let n = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    n -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) n -= 36;
  }
  return n;
}

// Total codewords (data + error correction) for a version; leftover bits are
// the remainder bits of Table 1.
function qrTotalCodewords(version) {
  return Math.floor(qrDataModuleCount(version) / 8);
}

// Data codewords available to the bit stream for a version and ECC level.
function qrDataCodewords(version, ecc) {
  return qrTotalCodewords(version) - QR_EC_PER_BLOCK[ecc][version] * QR_NUM_BLOCKS[ecc][version];
}

// Bits used by the mode indicator plus the character count indicator
// (clauses 7.4.1, 7.4.3, Table 3).
function qrHeaderBits(version) {
  return version <= 9 ? 4 + 8 : 4 + 16;
}

// Byte-mode payload capacity in bytes (ISO/IEC 18004 Table 7, Byte column).
function qrByteCapacity(version, ecc) {
  return Math.floor((qrDataCodewords(version, ecc) * 8 - qrHeaderBits(version)) / 8);
}

export const QR_CAPACITY = (() => {
  const table = [null];
  for (let v = 1; v <= 40; v++) {
    const row = {};
    for (const ecc of QR_ECC_LEVELS) row[ecc] = qrByteCapacity(v, ecc);
    table.push(Object.freeze(row));
  }
  return Object.freeze(table);
})();

// Alignment pattern centre coordinates (clause 6.3.6, Table E.1).
function qrAlignmentPositions(version) {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const positions = [6];
  for (let pos = version * 4 + 10; positions.length < count; pos -= step) positions.splice(1, 0, pos);
  return positions;
}

// ---------------------------------------------------------------------------
// E1.3  Data encoding (clauses 7.4.3, 7.4.9, 7.4.10)
// ---------------------------------------------------------------------------

function qrPickVersion(byteLength, ecc) {
  for (let v = 1; v <= 40; v++) {
    if (QR_CAPACITY[v][ecc] >= byteLength) return v;
  }
  throw new Error(
    `qrMatrix: ${byteLength} bytes exceeds the version 40 ${ecc} capacity of ${QR_CAPACITY[40][ecc]} bytes`,
  );
}

// Byte-mode bit stream, padded out to the full data codeword count.
function qrDataCodewordStream(bytes, version, ecc) {
  const total = qrDataCodewords(version, ecc);
  const bits = [];
  const push = (value, count) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };

  push(0b0100, 4); // byte mode indicator
  push(bytes.length, version <= 9 ? 8 : 16); // character count indicator
  for (let i = 0; i < bytes.length; i++) push(bytes[i], 8);

  // Terminator: up to four zero bits, truncated at the capacity boundary.
  const capacityBits = total * 8;
  const terminator = Math.min(4, capacityBits - bits.length);
  push(0, terminator);
  // Pad to a codeword boundary.
  push(0, (8 - (bits.length % 8)) % 8);

  const out = new Uint8Array(total);
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) out[i >>> 3] |= 0x80 >>> (i & 7);
  }
  // Fill the remaining data codewords with the alternating pad codewords.
  for (let i = bits.length / 8, pad = 0; i < total; i++, pad++) {
    out[i] = pad % 2 === 0 ? 0xec : 0x11;
  }
  return out;
}

// ---------------------------------------------------------------------------
// E1.4  Block splitting and interleaving (clause 7.6, Table 9)
// ---------------------------------------------------------------------------

function qrInterleave(dataCodewords, version, ecc) {
  const numBlocks = QR_NUM_BLOCKS[ecc][version];
  const ecLen = QR_EC_PER_BLOCK[ecc][version];
  const rawCodewords = qrTotalCodewords(version);
  // The first `shortCount` blocks hold `shortLen` data codewords, the rest
  // hold one more (Table 9 group 1 and group 2).
  const shortLen = Math.floor(rawCodewords / numBlocks) - ecLen;
  const shortCount = numBlocks - (rawCodewords % numBlocks);

  const dataBlocks = [];
  const ecBlocks = [];
  for (let b = 0, offset = 0; b < numBlocks; b++) {
    const len = shortLen + (b < shortCount ? 0 : 1);
    const block = dataCodewords.subarray(offset, offset + len);
    offset += len;
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecLen));
  }

  const out = new Uint8Array(rawCodewords);
  let k = 0;
  for (let i = 0; i <= shortLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < dataBlocks[b].length) out[k++] = dataBlocks[b][i];
    }
  }
  for (let i = 0; i < ecLen; i++) {
    for (let b = 0; b < numBlocks; b++) out[k++] = ecBlocks[b][i];
  }
  return out;
}

// ---------------------------------------------------------------------------
// E1.5  Function patterns (clauses 6.3.3 - 6.3.6)
// ---------------------------------------------------------------------------

function qrNewGrid(size, value) {
  const grid = [];
  for (let i = 0; i < size; i++) grid.push(new Array(size).fill(value));
  return grid;
}

function qrDrawFunctionPatterns(modules, isFunction, version) {
  const size = modules.length;
  const set = (row, col, dark) => {
    if (row < 0 || col < 0 || row >= size || col >= size) return;
    modules[row][col] = dark;
    isFunction[row][col] = true;
  };

  // Timing patterns (clause 6.3.5).
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }

  // Finder patterns plus their separators (clauses 6.3.3, 6.3.4).
  for (const [baseRow, baseCol] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const dist = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
        set(baseRow + dr, baseCol + dc, dist !== 2 && dist <= 3);
      }
    }
  }

  // Alignment patterns (clause 6.3.6); skipped where they would overlap a finder.
  const centres = qrAlignmentPositions(version);
  for (let i = 0; i < centres.length; i++) {
    for (let j = 0; j < centres.length; j++) {
      const skip = (i === 0 && j === 0)
        || (i === 0 && j === centres.length - 1)
        || (i === centres.length - 1 && j === 0);
      if (skip) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          set(centres[i] + dr, centres[j] + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  // Reserve the format information areas and the dark module (clause 7.9).
  // Column 6 and row 6 are timing patterns and are not part of the areas.
  for (let i = 0; i <= 8; i++) {
    if (i === 6) continue;
    set(i, 8, false);
    set(8, i, false);
  }
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, false);
  for (let i = 0; i < 7; i++) set(size - 1 - i, 8, false);
  set(size - 8, 8, true); // dark module at (4V+9, 8)

  // Reserve the version information areas (clause 7.10).
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(b, a, false);
      set(a, b, false);
    }
  }
}

// ---------------------------------------------------------------------------
// E1.6  Symbol character placement (clause 7.7.3)
// ---------------------------------------------------------------------------

function qrPlaceCodewords(modules, isFunction, codewords) {
  const size = modules.length;
  let bit = 0;
  const totalBits = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // the vertical timing pattern column is skipped
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const col = right - j;
        const upward = ((right + 1) & 2) === 0;
        const row = upward ? size - 1 - vert : vert;
        if (!isFunction[row][col] && bit < totalBits) {
          modules[row][col] = ((codewords[bit >>> 3] >>> (7 - (bit & 7))) & 1) === 1;
          bit++;
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// E1.7  Masking (clauses 7.8.2, 7.8.3) and format/version information
// ---------------------------------------------------------------------------

function qrMaskBit(mask, row, col) {
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

function qrApplyMask(modules, isFunction, mask) {
  const size = modules.length;
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (!isFunction[row][col] && qrMaskBit(mask, row, col)) {
        modules[row][col] = !modules[row][col];
      }
    }
  }
}

const QR_N1 = 3;
const QR_N2 = 3;
const QR_N3 = 40;
const QR_N4 = 10;
// The 1:1:3:1:1 finder-like sequence with its four-module light area, in both
// orientations (clause 7.8.3.1, rule N3).
const QR_N3_A = [true, false, true, true, true, false, true, false, false, false, false];
const QR_N3_B = [false, false, false, false, true, false, true, true, true, false, true];

function qrMatchesAt(line, pattern, start) {
  for (let i = 0; i < pattern.length; i++) {
    if (line[start + i] !== pattern[i]) return false;
  }
  return true;
}

function qrLinePenalty(line) {
  let penalty = 0;
  // N1: runs of five or more modules of the same colour.
  let runLength = 1;
  for (let i = 1; i < line.length; i++) {
    if (line[i] === line[i - 1]) {
      runLength++;
    } else {
      if (runLength >= 5) penalty += QR_N1 + (runLength - 5);
      runLength = 1;
    }
  }
  if (runLength >= 5) penalty += QR_N1 + (runLength - 5);

  // N3: finder-like patterns. The quiet zone is light, so the four-module
  // light area may fall outside the symbol; scan with light padding at both ends.
  const padded = [false, false, false, false].concat(line, [false, false, false, false]);
  for (let i = 0; i + 11 <= padded.length; i++) {
    if (qrMatchesAt(padded, QR_N3_A, i) || qrMatchesAt(padded, QR_N3_B, i)) penalty += QR_N3;
  }
  return penalty;
}

function qrPenalty(modules) {
  const size = modules.length;
  let penalty = 0;

  for (let row = 0; row < size; row++) penalty += qrLinePenalty(modules[row]);
  const column = new Array(size);
  for (let col = 0; col < size; col++) {
    for (let row = 0; row < size; row++) column[row] = modules[row][col];
    penalty += qrLinePenalty(column);
  }

  // N2: 2x2 blocks of one colour.
  let dark = 0;
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (modules[row][col]) dark++;
      if (row + 1 < size && col + 1 < size) {
        const c = modules[row][col];
        if (c === modules[row][col + 1] && c === modules[row + 1][col] && c === modules[row + 1][col + 1]) {
          penalty += QR_N2;
        }
      }
    }
  }

  // N4: deviation of the dark module proportion from 50%, in 5% steps.
  const total = size * size;
  const k = Math.floor(Math.abs(dark * 20 - total * 10) / total);
  penalty += QR_N4 * k;

  return penalty;
}

// BCH remainder of `value` modulo `generator` (degree `degree`).
function qrBchRemainder(value, generator, degree) {
  let rem = value;
  for (let i = degree - 1; i >= 0; i--) {
    if (rem >>> (degree + i) & 1) rem ^= generator << i;
  }
  return rem;
}

const QR_ECC_INDICATOR = { L: 0b01, M: 0b00, Q: 0b11, H: 0b10 };

// 15-bit format information: 5 data bits, BCH(15,5), XOR 0x5412 (clause 7.9).
function qrFormatBits(ecc, mask) {
  const data = (QR_ECC_INDICATOR[ecc] << 3) | mask;
  const rem = qrBchRemainder(data << 10, 0b10100110111, 10);
  return ((data << 10) | rem) ^ 0x5412;
}

// 18-bit version information: 6 data bits, BCH(18,6) (clause 7.10).
function qrVersionBits(version) {
  const rem = qrBchRemainder(version << 12, 0b1111100100101, 12);
  return (version << 12) | rem;
}

function qrDrawFormatBits(modules, ecc, mask) {
  const size = modules.length;
  const bits = qrFormatBits(ecc, mask);
  const bit = (i) => ((bits >>> i) & 1) === 1;

  // Copy 1, around the top-left finder.
  for (let i = 0; i <= 5; i++) modules[i][8] = bit(i);
  modules[7][8] = bit(6);
  modules[8][8] = bit(7);
  modules[8][7] = bit(8);
  for (let i = 9; i < 15; i++) modules[8][14 - i] = bit(i);

  // Copy 2, split between the top-right and bottom-left finders.
  for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = bit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = bit(i);
  modules[size - 8][8] = true; // dark module
}

function qrDrawVersionBits(modules, version) {
  if (version < 7) return;
  const size = modules.length;
  const bits = qrVersionBits(version);
  for (let i = 0; i < 18; i++) {
    const dark = ((bits >>> i) & 1) === 1;
    const a = size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    modules[b][a] = dark;
    modules[a][b] = dark;
  }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export function qrMatrix(bytes, { ecc = 'M' } = {}) {
  const level = String(ecc).toUpperCase();
  if (!QR_ECC_LEVELS.includes(level)) throw new Error(`qrMatrix: unknown ECC level ${ecc}`);
  const data = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes || []);

  const version = qrPickVersion(data.length, level);
  const size = 21 + 4 * (version - 1);

  const codewords = qrInterleave(qrDataCodewordStream(data, version, level), version, level);

  const modules = qrNewGrid(size, false);
  const isFunction = qrNewGrid(size, false);
  qrDrawFunctionPatterns(modules, isFunction, version);
  qrDrawVersionBits(modules, version);
  qrPlaceCodewords(modules, isFunction, codewords);

  // Choose the mask with the lowest penalty score (clause 7.8.3).
  let bestMask = 0;
  let bestPenalty = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    qrApplyMask(modules, isFunction, mask);
    qrDrawFormatBits(modules, level, mask);
    const penalty = qrPenalty(modules);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMask = mask;
    }
    qrApplyMask(modules, isFunction, mask); // undo
  }

  qrApplyMask(modules, isFunction, bestMask);
  qrDrawFormatBits(modules, level, bestMask);

  return modules;
}
