(function exposeSigninQr(root, factory) {
  "use strict";

  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.SigninQr = Object.freeze(api);
})(typeof window === "undefined" ? null : window, function createSigninQr() {
  "use strict";

  const BLOCK_GROUPS_M = Object.freeze([
    Object.freeze([[1, 16, 10]]),
    Object.freeze([[1, 28, 16]]),
    Object.freeze([[1, 44, 26]]),
    Object.freeze([[2, 32, 18]]),
    Object.freeze([[2, 43, 24]]),
    Object.freeze([[4, 27, 16]]),
    Object.freeze([[4, 31, 18]]),
    Object.freeze([[2, 38, 22], [2, 39, 22]]),
    Object.freeze([[3, 36, 22], [2, 37, 22]]),
    Object.freeze([[4, 43, 26], [1, 44, 26]]),
  ]);
  const ALIGNMENT_CENTERS = Object.freeze([
    null,
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34],
    [6, 22, 38],
    [6, 24, 42],
    [6, 26, 46],
    [6, 28, 50],
  ]);
  const FORMAT_MASK = 0x5412;
  const FORMAT_POLYNOMIAL = 0x537;
  const VERSION_POLYNOMIAL = 0x1f25;

  function multiplyGf256(left, right) {
    let product = 0;
    for (let bit = 7; bit >= 0; bit -= 1) {
      product = (product << 1) ^ ((product >>> 7) * 0x11d);
      product ^= ((right >>> bit) & 1) * left;
    }
    return product;
  }

  function appendBits(bits, value, length) {
    if (length < 0 || length > 31 || value < 0 || value >>> length !== 0) {
      throw new Error("QR_DATA_INVALID");
    }
    for (let shift = length - 1; shift >= 0; shift -= 1) bits.push((value >>> shift) & 1);
  }

  function dataCodewords(version) {
    return BLOCK_GROUPS_M[version - 1]
      .reduce((total, [count, dataLength]) => total + count * dataLength, 0);
  }

  function selectVersion(byteLength) {
    for (let version = 1; version <= 10; version += 1) {
      const countBits = version <= 9 ? 8 : 16;
      const required = 4 + countBits + byteLength * 8;
      if (byteLength < (1 << countBits) && required <= dataCodewords(version) * 8) return version;
    }
    return 0;
  }

  function makeDataCodewords(bytes, version) {
    const capacity = dataCodewords(version) * 8;
    const bits = [];
    appendBits(bits, 0b0100, 4);
    appendBits(bits, bytes.length, version <= 9 ? 8 : 16);
    for (const byte of bytes) appendBits(bits, byte, 8);
    appendBits(bits, 0, Math.min(4, capacity - bits.length));
    while (bits.length % 8 !== 0) bits.push(0);
    const result = [];
    for (let offset = 0; offset < bits.length; offset += 8) {
      let value = 0;
      for (let bit = 0; bit < 8; bit += 1) value = (value << 1) | bits[offset + bit];
      result.push(value);
    }
    for (let pad = 0; result.length < capacity / 8; pad += 1) {
      result.push(pad % 2 === 0 ? 0xec : 0x11);
    }
    return result;
  }

  function makeDivisor(degree) {
    const result = Array(degree).fill(0);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i += 1) {
      for (let j = 0; j < degree; j += 1) {
        result[j] = multiplyGf256(result[j], root);
        if (j + 1 < degree) result[j] ^= result[j + 1];
      }
      root = multiplyGf256(root, 2);
    }
    return result;
  }

  function makeRemainder(data, divisor) {
    const result = Array(divisor.length).fill(0);
    for (const byte of data) {
      const factor = byte ^ result[0];
      result.copyWithin(0, 1);
      result[result.length - 1] = 0;
      for (let i = 0; i < result.length; i += 1) {
        result[i] ^= multiplyGf256(divisor[i], factor);
      }
    }
    return result;
  }

  function makeCodewords(data, version) {
    const blocks = [];
    for (const [count, dataLength, eccLength] of BLOCK_GROUPS_M[version - 1]) {
      const divisor = makeDivisor(eccLength);
      for (let i = 0; i < count; i += 1) {
        const part = data.slice(0, dataLength);
        data = data.slice(dataLength);
        blocks.push({ data: part, ecc: makeRemainder(part, divisor) });
      }
    }
    if (data.length !== 0) throw new Error("QR_BLOCK_LAYOUT_INVALID");
    const result = [];
    const maxDataLength = Math.max(...blocks.map((block) => block.data.length));
    const eccLength = blocks[0].ecc.length;
    for (let i = 0; i < maxDataLength; i += 1) {
      for (const block of blocks) if (i < block.data.length) result.push(block.data[i]);
    }
    for (let i = 0; i < eccLength; i += 1) {
      for (const block of blocks) result.push(block.ecc[i]);
    }
    return result;
  }

  function bchRemainder(value, polynomial) {
    let remainder = value;
    const polynomialDegree = 31 - Math.clz32(polynomial);
    while (remainder !== 0 && 31 - Math.clz32(remainder) >= polynomialDegree) {
      remainder ^= polynomial << ((31 - Math.clz32(remainder)) - polynomialDegree);
    }
    return remainder;
  }

  function makeBaseMatrix(version) {
    const size = version * 4 + 17;
    const modules = Array.from({ length: size }, () => Array(size).fill(false));
    const reserved = Array.from({ length: size }, () => Array(size).fill(false));
    function setFunction(x, y, dark) {
      if (x < 0 || y < 0 || x >= size || y >= size) return;
      modules[y][x] = dark;
      reserved[y][x] = true;
    }
    function drawFinder(centerX, centerY) {
      for (let dy = -1; dy <= 7; dy += 1) {
        for (let dx = -1; dx <= 7; dx += 1) {
          const x = centerX + dx;
          const y = centerY + dy;
          const distance = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
          setFunction(x, y, distance !== 2 && distance !== 4);
        }
      }
    }
    function drawAlignment(centerX, centerY) {
      for (let dy = -2; dy <= 2; dy += 1) {
        for (let dx = -2; dx <= 2; dx += 1) {
          setFunction(centerX + dx, centerY + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
    drawFinder(0, 0);
    drawFinder(size - 7, 0);
    drawFinder(0, size - 7);
    for (let i = 8; i < size - 8; i += 1) {
      setFunction(6, i, i % 2 === 0);
      setFunction(i, 6, i % 2 === 0);
    }
    const centers = ALIGNMENT_CENTERS[version - 1];
    if (centers) {
      for (const y of centers) {
        for (const x of centers) {
          const overlapsFinder = (x === 6 && y === 6)
            || (x === 6 && y === size - 7)
            || (x === size - 7 && y === 6);
          if (!overlapsFinder) drawAlignment(x, y);
        }
      }
    }
    drawFormatBits(modules, reserved, 0);
    if (version >= 7) {
      const bits = (version << 12) | bchRemainder(version << 12, VERSION_POLYNOMIAL);
      for (let i = 0; i < 18; i += 1) {
        const dark = ((bits >>> i) & 1) !== 0;
        const a = size - 11 + (i % 3);
        const b = Math.floor(i / 3);
        setFunction(a, b, dark);
        setFunction(b, a, dark);
      }
    }
    return { size, modules, reserved };
  }

  function drawFormatBits(modules, reserved, mask) {
    const size = modules.length;
    const data = mask;
    const bits = ((data << 10) | bchRemainder(data << 10, FORMAT_POLYNOMIAL)) ^ FORMAT_MASK;
    function set(x, y, bit) {
      modules[y][x] = ((bits >>> bit) & 1) !== 0;
      reserved[y][x] = true;
    }
    for (let i = 0; i <= 5; i += 1) set(8, i, i);
    set(8, 7, 6);
    set(8, 8, 7);
    set(7, 8, 8);
    for (let i = 9; i < 15; i += 1) set(14 - i, 8, i);
    for (let i = 0; i < 8; i += 1) set(size - 1 - i, 8, i);
    for (let i = 8; i < 15; i += 1) set(8, size - 15 + i, i);
    modules[size - 8][8] = true;
    reserved[size - 8][8] = true;
  }

  function maskBit(mask, x, y) {
    switch (mask) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
      case 5: return (x * y) % 2 + (x * y) % 3 === 0;
      case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0;
      case 7: return ((x + y) % 2 + (x * y) % 3) % 2 === 0;
      default: return false;
    }
  }

  function drawData(modules, reserved, codewords, mask) {
    const size = modules.length;
    let bitIndex = 0;
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let step = 0; step < size; step += 1) {
        const y = upward ? size - 1 - step : step;
        for (let offset = 0; offset < 2; offset += 1) {
          const x = right - offset;
          if (reserved[y][x]) continue;
          const value = bitIndex < codewords.length * 8
            && ((codewords[Math.floor(bitIndex / 8)] >>> (7 - bitIndex % 8)) & 1) !== 0;
          modules[y][x] = value !== maskBit(mask, x, y);
          bitIndex += 1;
        }
      }
      upward = !upward;
    }
  }

  function linePenalty(line) {
    let score = 0;
    let runColor = line[0];
    let runLength = 1;
    for (let i = 1; i <= line.length; i += 1) {
      if (i < line.length && line[i] === runColor) {
        runLength += 1;
      } else {
        if (runLength >= 5) score += runLength - 2;
        if (i < line.length) {
          runColor = line[i];
          runLength = 1;
        }
      }
    }
    for (let start = 0; start + 11 <= line.length; start += 1) {
      let pattern = 0;
      for (let offset = 0; offset < 11; offset += 1) {
        pattern = (pattern << 1) | (line[start + offset] ? 1 : 0);
      }
      if (pattern === 0b00001011101 || pattern === 0b10111010000) score += 40;
    }
    return score;
  }

  function penaltyScore(modules) {
    const size = modules.length;
    let score = 0;
    for (let y = 0; y < size; y += 1) score += linePenalty(modules[y]);
    for (let x = 0; x < size; x += 1) {
      score += linePenalty(modules.map((row) => row[x]));
    }
    for (let y = 0; y < size - 1; y += 1) {
      for (let x = 0; x < size - 1; x += 1) {
        const value = modules[y][x];
        if (modules[y][x + 1] === value && modules[y + 1][x] === value
          && modules[y + 1][x + 1] === value) score += 3;
      }
    }
    let dark = 0;
    for (const row of modules) for (const value of row) if (value) dark += 1;
    score += Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
    return score;
  }

  function encodeMatrix(text) {
    if (typeof text !== "string" || text.length === 0 || text.length > 4096) return null;
    const bytes = Array.from(new TextEncoder().encode(text));
    const version = selectVersion(bytes.length);
    if (version === 0) return null;
    const data = makeDataCodewords(bytes, version);
    const codewords = makeCodewords(data, version);
    const base = makeBaseMatrix(version);
    let best = null;
    let bestPenalty = Infinity;
    for (let mask = 0; mask < 8; mask += 1) {
      const modules = base.modules.map((row) => row.slice());
      drawFormatBits(modules, base.reserved.map((row) => row.slice()), mask);
      drawData(modules, base.reserved, codewords, mask);
      const penalty = penaltyScore(modules);
      if (penalty < bestPenalty) {
        best = modules;
        bestPenalty = penalty;
      }
    }
    return { version, size: base.size, modules: best };
  }

  function isTotpUri(value) {
    if (typeof value !== "string" || value.length === 0 || value.length > 4096) return false;
    try {
      const uri = new URL(value);
      const secrets = uri.searchParams.getAll("secret");
      if (uri.protocol !== "otpauth:" || uri.hostname !== "totp"
        || uri.username !== "" || uri.password !== "" || uri.port !== ""
        || uri.hash !== "" || !uri.pathname.replaceAll("/", "") || secrets.length !== 1) {
        return false;
      }
      const secret = secrets[0].toUpperCase();
      const unpadded = secret.replace(/=+$/, "");
      const padding = secret.length - unpadded.length;
      return /^[A-Z2-7]+$/.test(unpadded) && padding <= 6
        && /^=*$/.test(secret.slice(unpadded.length));
    } catch {
      return false;
    }
  }

  function renderOtpauthQr(container, uri) {
    if (!container || typeof container.replaceChildren !== "function"
      || typeof document === "undefined" || !isTotpUri(uri)) return false;
    const encoded = encodeMatrix(uri);
    if (!encoded) return false;
    const quietZone = 4;
    const viewSize = encoded.size + quietZone * 2;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", `0 0 ${viewSize} ${viewSize}`);
    svg.setAttribute("width", "192");
    svg.setAttribute("height", "192");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Authenticator setup QR code");
    svg.setAttribute("shape-rendering", "crispEdges");
    const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    background.setAttribute("width", String(viewSize));
    background.setAttribute("height", String(viewSize));
    background.setAttribute("fill", "#fff");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    let commands = "";
    for (let y = 0; y < encoded.size; y += 1) {
      for (let x = 0; x < encoded.size; x += 1) {
        if (encoded.modules[y][x]) commands += `M${x + quietZone},${y + quietZone}h1v1h-1z`;
      }
    }
    path.setAttribute("d", commands);
    path.setAttribute("fill", "#000");
    svg.appendChild(background);
    svg.appendChild(path);
    container.replaceChildren(svg);
    return true;
  }

  function clearOtpauthQr(container) {
    if (container && typeof container.replaceChildren === "function") container.replaceChildren();
  }

  return Object.freeze({ renderOtpauthQr, clearOtpauthQr });
});
