// Minimal QR code encoder (byte mode, error correction level M, versions 1-20) that
// returns an SVG string. Used for the two-factor setup code; no external libraries.
(function exportQr(global) {
  // [EC codewords per block, group 1 blocks, data codewords, group 2 blocks, data codewords]
  const blocksM = [null, [10, 1, 16, 0, 0], [16, 1, 28, 0, 0], [26, 1, 44, 0, 0], [18, 2, 32, 0, 0], [24, 2, 43, 0, 0],
    [16, 4, 27, 0, 0], [18, 4, 31, 0, 0], [22, 2, 38, 2, 39], [22, 3, 36, 2, 37], [26, 4, 43, 1, 44], [30, 1, 50, 4, 51],
    [22, 6, 36, 2, 37], [22, 8, 37, 1, 38], [24, 4, 40, 5, 41], [24, 5, 41, 5, 42], [28, 7, 45, 3, 46], [28, 10, 46, 1, 47],
    [26, 9, 43, 4, 44], [26, 3, 44, 11, 45], [26, 3, 41, 13, 42]];
  const alignment = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
    [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82],
    [6, 30, 58, 86], [6, 34, 62, 90]];
  const remainderBits = [0, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3];

  const exp = new Array(512);
  const log = new Array(256);
  for (let index = 0, value = 1; index < 255; index += 1) {
    exp[index] = value;
    log[value] = index;
    value <<= 1;
    if (value & 256) value ^= 0x11d;
  }
  for (let index = 255; index < 512; index += 1) exp[index] = exp[index - 255];
  const multiply = (left, right) => (left && right ? exp[log[left] + log[right]] : 0);

  function generator(degree) {
    let poly = [1];
    for (let index = 0; index < degree; index += 1) {
      const next = new Array(poly.length + 1).fill(0);
      poly.forEach((coefficient, position) => {
        next[position] ^= coefficient;
        next[position + 1] ^= multiply(coefficient, exp[index]);
      });
      poly = next;
    }
    return poly;
  }

  function errorCorrection(data, degree) {
    const gen = generator(degree);
    const result = new Array(degree).fill(0);
    for (const byte of data) {
      const factor = byte ^ result.shift();
      result.push(0);
      for (let index = 0; index < degree; index += 1) result[index] ^= multiply(gen[index + 1], factor);
    }
    return result;
  }

  function encodeCodewords(bytes, version) {
    const [ecLength, groupOne, dataOne, groupTwo, dataTwo] = blocksM[version];
    const capacity = groupOne * dataOne + groupTwo * dataTwo;
    const bits = [];
    const push = (value, length) => {
      for (let index = length - 1; index >= 0; index -= 1) bits.push((value >>> index) & 1);
    };
    push(4, 4);
    push(bytes.length, version < 10 ? 8 : 16);
    bytes.forEach((byte) => push(byte, 8));
    push(0, Math.min(4, capacity * 8 - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let index = 0; index < bits.length; index += 8) data.push(parseInt(bits.slice(index, index + 8).join(""), 2));
    for (let pad = 0; data.length < capacity; pad += 1) data.push(pad % 2 ? 0x11 : 0xec);
    const blocks = [];
    let offset = 0;
    for (let index = 0; index < groupOne + groupTwo; index += 1) {
      const length = index < groupOne ? dataOne : dataTwo;
      const block = data.slice(offset, offset + length);
      offset += length;
      blocks.push({ data: block, ec: errorCorrection(block, ecLength) });
    }
    const result = [];
    for (let index = 0; index < Math.max(dataOne, dataTwo); index += 1) {
      blocks.forEach((block) => { if (index < block.data.length) result.push(block.data[index]); });
    }
    for (let index = 0; index < ecLength; index += 1) blocks.forEach((block) => result.push(block.ec[index]));
    return result;
  }

  function buildMatrix(codewords, version, mask) {
    const size = version * 4 + 17;
    const modules = Array.from({ length: size }, () => new Array(size).fill(false));
    const reserved = Array.from({ length: size }, () => new Array(size).fill(false));
    const set = (x, y, dark) => {
      modules[y][x] = dark;
      reserved[y][x] = true;
    };
    for (let index = 0; index < size; index += 1) {
      set(6, index, index % 2 === 0);
      set(index, 6, index % 2 === 0);
    }
    const finder = (centerX, centerY) => {
      for (let dy = -4; dy <= 4; dy += 1) {
        for (let dx = -4; dx <= 4; dx += 1) {
          const x = centerX + dx;
          const y = centerY + dy;
          if (x < 0 || y < 0 || x >= size || y >= size) continue;
          const distance = Math.max(Math.abs(dx), Math.abs(dy));
          set(x, y, distance !== 2 && distance !== 4);
        }
      }
    };
    finder(3, 3);
    finder(size - 4, 3);
    finder(3, size - 4);
    const positions = alignment[version];
    positions.forEach((row, rowIndex) => positions.forEach((column, columnIndex) => {
      const last = positions.length - 1;
      if ((rowIndex === 0 && columnIndex === 0) || (rowIndex === 0 && columnIndex === last) || (rowIndex === last && columnIndex === 0)) return;
      for (let dy = -2; dy <= 2; dy += 1) {
        for (let dx = -2; dx <= 2; dx += 1) set(column + dx, row + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }));
    // Format information (level M = 0) with the BCH code, in both copies.
    const formatData = (0 << 3) | mask;
    let remainder = formatData;
    for (let index = 0; index < 10; index += 1) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
    const format = ((formatData << 10) | remainder) ^ 0x5412;
    const formatBit = (index) => ((format >>> index) & 1) === 1;
    for (let index = 0; index <= 5; index += 1) set(8, index, formatBit(index));
    set(8, 7, formatBit(6));
    set(8, 8, formatBit(7));
    set(7, 8, formatBit(8));
    for (let index = 9; index < 15; index += 1) set(14 - index, 8, formatBit(index));
    for (let index = 0; index < 8; index += 1) set(size - 1 - index, 8, formatBit(index));
    for (let index = 8; index < 15; index += 1) set(8, size - 15 + index, formatBit(index));
    set(8, size - 8, true);
    if (version >= 7) {
      let versionRemainder = version;
      for (let index = 0; index < 12; index += 1) versionRemainder = (versionRemainder << 1) ^ ((versionRemainder >>> 11) * 0x1f25);
      const versionBits = (version << 12) | versionRemainder;
      for (let index = 0; index < 18; index += 1) {
        const dark = ((versionBits >>> index) & 1) === 1;
        const a = size - 11 + (index % 3);
        const b = Math.floor(index / 3);
        set(a, b, dark);
        set(b, a, dark);
      }
    }
    const bits = [];
    codewords.forEach((byte) => { for (let index = 7; index >= 0; index -= 1) bits.push((byte >>> index) & 1); });
    for (let index = 0; index < remainderBits[version]; index += 1) bits.push(0);
    const masks = [
      (x, y) => (x + y) % 2 === 0, (_x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
      (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
      (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
    ];
    let bitIndex = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vertical = 0; vertical < size; vertical += 1) {
        for (let column = 0; column < 2; column += 1) {
          const x = right - column;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vertical : vertical;
          if (reserved[y][x]) continue;
          const dark = bitIndex < bits.length ? bits[bitIndex] === 1 : false;
          bitIndex += 1;
          modules[y][x] = dark !== masks[mask](x, y);
        }
      }
    }
    return modules;
  }

  // Penalty rules 1, 2 and 4 of the standard; enough to avoid badly balanced masks.
  function penalty(modules) {
    const size = modules.length;
    let score = 0;
    for (let line = 0; line < size; line += 1) {
      for (const read of [(index) => modules[line][index], (index) => modules[index][line]]) {
        let run = 1;
        for (let index = 1; index < size; index += 1) {
          if (read(index) === read(index - 1)) {
            run += 1;
            if (run === 5) score += 3;
            else if (run > 5) score += 1;
          } else run = 1;
        }
      }
    }
    let dark = 0;
    for (let y = 0; y < size; y += 1) {
      for (let x = 0; x < size; x += 1) {
        if (modules[y][x]) dark += 1;
        if (x < size - 1 && y < size - 1) {
          const color = modules[y][x];
          if (color === modules[y][x + 1] && color === modules[y + 1][x] && color === modules[y + 1][x + 1]) score += 3;
        }
      }
    }
    score += Math.floor(Math.abs((dark * 20) / (size * size) - 10)) * 10;
    return score;
  }

  function qrMatrix(text) {
    const bytes = [...new TextEncoder().encode(String(text))];
    let version = 1;
    while (version <= 20) {
      const [, groupOne, dataOne, groupTwo, dataTwo] = blocksM[version];
      const headerBits = 4 + (version < 10 ? 8 : 16);
      if (headerBits + bytes.length * 8 <= (groupOne * dataOne + groupTwo * dataTwo) * 8) break;
      version += 1;
    }
    if (version > 20) throw new Error("Text is too long for a QR code.");
    const codewords = encodeCodewords(bytes, version);
    let best = null;
    for (let mask = 0; mask < 8; mask += 1) {
      const modules = buildMatrix(codewords, version, mask);
      const score = penalty(modules);
      if (!best || score < best.score) best = { modules, score };
    }
    return best.modules;
  }

  function qrSvg(text, { quiet = 4 } = {}) {
    const modules = qrMatrix(text);
    const size = modules.length + quiet * 2;
    let path = "";
    modules.forEach((row, y) => row.forEach((dark, x) => {
      if (dark) path += `M${x + quiet} ${y + quiet}h1v1h-1z`;
    }));
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
  }

  global.qrMatrix = qrMatrix;
  global.qrSvg = qrSvg;
}(typeof window === "undefined" ? globalThis : window));
