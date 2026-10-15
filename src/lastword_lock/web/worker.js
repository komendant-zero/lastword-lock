/**
 * High-performance SHA-256 Mining Worker for Web Browsers.
 * Evaluates single-block (24 bytes: 16-byte salt + 8-byte nonce) pre-image checks.
 * Uses optimized 32-bit integer bitwise operations with zero allocations in loop.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

let isStopped = false;
const W = new Uint32Array(64);
const targetWords = new Uint32Array(8);

// Pre-fill padding constants for 24-byte input
W[6] = 0x80000000;
W[7] = 0; W[8] = 0; W[9] = 0; W[10] = 0;
W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
W[15] = 192; // 24 bytes * 8 bits = 192 bits

function checkNonce(n) {
  // Set 64-bit nonce into W[4] and W[5]
  W[4] = Math.floor(n / 0x100000000) >>> 0;
  W[5] = (n % 0x100000000) >>> 0;

  // Expansion
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
    const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
  }

  // Initial hash values
  let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
  let e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

  // Compression
  for (let i = 0; i < 64; i++) {
    const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ ((~e) & g);
    const temp1 = (h + s1 + ch + K[i] + W[i]) >>> 0;
    const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (s0 + maj) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  const h0 = (a + 0x6a09e667) >>> 0;
  if (h0 !== targetWords[0]) return false;

  const h1 = (b + 0xbb67ae85) >>> 0;
  if (h1 !== targetWords[1]) return false;

  const h2 = (c + 0x3c6ef372) >>> 0;
  if (h2 !== targetWords[2]) return false;

  const h3 = (d + 0xa54ff53a) >>> 0;
  if (h3 !== targetWords[3]) return false;

  const h4 = (e + 0x510e527f) >>> 0;
  if (h4 !== targetWords[4]) return false;

  const h5 = (f + 0x9b05688c) >>> 0;
  if (h5 !== targetWords[5]) return false;

  const h6 = (g + 0x1f83d9ab) >>> 0;
  if (h6 !== targetWords[6]) return false;

  const h7 = (h + 0x5be0cd19) >>> 0;
  return h7 === targetWords[7];
}

self.onmessage = function (e) {
  const msg = e.data;
  if (msg.type === "INIT") {
    // Fill salt words
    W[0] = msg.saltWords[0];
    W[1] = msg.saltWords[1];
    W[2] = msg.saltWords[2];
    W[3] = msg.saltWords[3];
    // Fill target words
    for (let i = 0; i < 8; i++) {
      targetWords[i] = msg.targetWords[i];
    }
  } else if (msg.type === "STOP") {
    isStopped = true;
  } else if (msg.type === "MINE") {
    isStopped = false;
    const start = msg.start;
    const end = msg.end;
    const step = msg.step || 15000;
    const jobId = msg.jobId;

    let curr = start;
    while (curr < end) {
      if (isStopped) {
        self.postMessage({ type: "STOPPED", jobId });
        return;
      }
      const batchEnd = Math.min(curr + step, end);
      for (let n = curr; n < batchEnd; n++) {
        if (checkNonce(n)) {
          self.postMessage({ type: "FOUND", nonce: n, jobId });
          return;
        }
      }
      const doneBatch = batchEnd - curr;
      self.postMessage({ type: "PROGRESS", count: doneBatch, jobId });
      curr = batchEnd;
    }
    self.postMessage({ type: "DONE", jobId });
  }
};
