// =============================================================================
// evmKeccak.ts — 零依赖 keccak-256（Keccak-f[1600]，原始 0x01 填充，非 SHA3）。
//
// 用途（仅两类，均为公开数据的哈希，不涉及任何密钥材料）：
//   1) EIP-55 校验和地址派生（monadWallet.toEip55Address）；
//   2) EIP-191 personal_sign 消息摘要（monad 登录凭证的 messageHash）。
//
// 事件 topic0 等常量不在运行时计算——由 cast sig-event 离线算好硬编码
// （见 monadSettlement.ts），本实现的单测用同一批向量反向锚定：
//   keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
//   keccak256("WrapSettled(uint256,uint256,uint256)") 必须复现
//   cast sig-event 输出 0x7018a142…106cbdc1。
// =============================================================================

const RATE_BYTES = 136; // 1088 bit，keccak-256 的吸收速率
const MASK64 = 0xffffffffffffffffn;

/** 轮常数 ι（24 轮，Keccak 参考）。 */
const ROUND_CONSTANTS: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** ρ 旋转偏移，扁平索引 = x + 5*y（Keccak 参考的 r[x][y] 表）。 */
const ROTATION_OFFSETS: number[] = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

function rotl64(v: bigint, n: bigint): bigint {
  const shifts = n % 64n;
  return ((v << shifts) | (v >> (64n - shifts))) & MASK64;
}

/** Keccak-f[1600]：24 轮 θ / ρπ / χ / ι，原位改写 25 个 64bit lane。 */
function keccakF(state: BigUint64Array): void {
  for (let round = 0; round < 24; round++) {
    // θ：列奇偶 + 邻列错位扩散
    const c = new BigUint64Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1n);
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d;
    }
    // ρ + π：旋转后搬到 B[y, (2x+3y) mod 5]
    const b = new BigUint64Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const src = x + 5 * y;
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[src], BigInt(ROTATION_OFFSETS[src]));
      }
    }
    // χ：行内非线性
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] =
          b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y] & MASK64) & b[(x + 2) % 5 + 5 * y]);
      }
    }
    // ι
    state[0] ^= ROUND_CONSTANTS[round];
  }
}

function readLeU64(buf: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(buf[offset + i]);
  }
  return v;
}

function writeLeU64(buf: Uint8Array, offset: number, v: bigint): void {
  for (let i = 0; i < 8; i++) {
    buf[offset + i] = Number((v >> BigInt(8 * i)) & 0xffn);
  }
}

/** keccak-256（原始 Keccak 填充 0x01，Ethereum 口径）。 */
export function keccak256Bytes(data: Uint8Array): Uint8Array {
  const state = new BigUint64Array(25);
  // 多率填充：消息后补 0x01，末字节 |= 0x80（len==RATE 时额外整块）。
  const paddedLen = (Math.floor((data.length + 1) / RATE_BYTES) + 1) * RATE_BYTES;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[data.length] = 0x01;
  padded[paddedLen - 1] |= 0x80;

  for (let offset = 0; offset < paddedLen; offset += RATE_BYTES) {
    for (let i = 0; i < RATE_BYTES / 8; i++) {
      state[i] ^= readLeU64(padded, offset + i * 8);
    }
    keccakF(state);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) writeLeU64(out, i * 8, state[i]);
  return out;
}

const HEX = '0123456789abcdef';

function toHex(bytes: Uint8Array): string {
  let s = '0x';
  for (const b of bytes) {
    s += HEX[b >> 4] + HEX[b & 0xf];
  }
  return s;
}

/** UTF-8 字符串的 keccak-256（0x 前缀 hex）。 */
export function keccak256Utf8(text: string): string {
  return toHex(keccak256Bytes(new TextEncoder().encode(text)));
}

/** 字节数组的 keccak-256（0x 前缀 hex）。 */
export function keccak256Hex(bytes: Uint8Array): string {
  return toHex(keccak256Bytes(bytes));
}

/**
 * EIP-191 personal_sign 消息摘要：
 * keccak("\x19Ethereum Signed Message:\n" + len(decimal) + message)。
 * 与钱包 personal_sign 实际签名的哈希一致（monad 登录凭证的 messageHash）。
 */
export function personalMessageHash(message: string): string {
  const payload = `\x19Ethereum Signed Message:\n${message.length}${message}`;
  return keccak256Utf8(payload);
}
