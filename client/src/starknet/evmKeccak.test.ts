/**
 * evmKeccak 单元测试——已知答案向量（KAT）锚定。
 *
 * 向量来源（本会话 2026-09-28 用 /Users/mac/.foundry/bin/cast 离线生成，
 * 与实现独立）：
 *   - keccak256("") / keccak256("abc")：官方 Keccak-256 已知答案；
 *   - 事件签名 topic：cast sig-event 输出（同 monadSettlement.ts 硬编码常量）；
 *   - 多块输入（216B > 136B 速率）：cast keccak；
 *   - EIP-191 personal_sign 摘要：python 构造前缀串 + cast keccak。
 */
import { describe, expect, it } from 'vitest';

import { keccak256Utf8, personalMessageHash } from './evmKeccak';
import {
  TOPIC_BATCH_ANCHORED,
  TOPIC_BATCH_SETTLED,
  TOPIC_WRAP_SETTLED,
} from './monadSettlement';

describe('evmKeccak', () => {
  it('空串命中官方 KAT', () => {
    expect(keccak256Utf8('')).toBe(
      '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    );
  });

  it('"abc" 命中官方 KAT（Keccak 0x01 填充，非 SHA3-256）', () => {
    expect(keccak256Utf8('abc')).toBe(
      '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
    );
  });

  it('多块输入（216B，跨 136B 速率边界）命中 cast keccak 向量', () => {
    const long = 'monad-settlement-vector-'.repeat(9);
    expect(long).toHaveLength(216);
    expect(keccak256Utf8(long)).toBe(
      '0x78ef8f6b1b5ab476bcb1947e3ab51b2121d2bd65d2d4f3a52ba1fc83d4f94df7',
    );
  });

  it('事件签名哈希复现 cast sig-event 的 topic0（与 monadSettlement 常量一致）', () => {
    expect(keccak256Utf8('WrapSettled(uint256,uint256,uint256)')).toBe(TOPIC_WRAP_SETTLED);
    expect(keccak256Utf8('BatchAnchored(uint64,bytes32,uint64)')).toBe(TOPIC_BATCH_ANCHORED);
    expect(keccak256Utf8('BatchSettled(address,bytes32,uint256,uint256,uint256)')).toBe(
      TOPIC_BATCH_SETTLED,
    );
  });

  it('EIP-191 personal_sign 摘要命中 cast 向量（真实 0x19 起始字节）', () => {
    // 向量重建：cast keccak 0x19457468…7a67616d652d6c6f67696e
    // = keccak(0x19 ‖ "Ethereum Signed Message:\n" ‖ "11" ‖ "zgame-login")
    expect(personalMessageHash('zgame-login')).toBe(
      '0x5320d7bb4915fc74b6e5e8dc0aab67e0f6e782379f342a76bc20ec4ac88f98b0',
    );
  });
});
