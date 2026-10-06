/**
 * monadSettlement 单元测试——事件解码与 getLogs 分片。
 *
 * 向量交叉验证（本会话 2026-09-28）：
 *   - topic0 常量来自 `cast sig-event`（并要求本地 keccak 复现，见
 *     evmKeccak.test.ts）；
 *   - BatchAnchored 的 data 段（root ‖ throughOp）布局经
 *     `cast abi-encode 'f(bytes32,uint64)' <root> 7` 产出比对；
 *   - index 的 topic 填充形态经 `cast abi-encode 'f(uint64)' 2` 产出比对。
 *
 * 真实链上事实（同日实测 testnet-rpc.monad.xyz）：batchCount() 返回 5，
 * 选择子 0x06f13056；eth_getLogs 窗口限 100 块（-32614）。
 */
import { describe, expect, it, vi } from 'vitest';

import {
  MONAD_L1_INBOX,
  SELECTOR_BATCH_COUNT,
  TOPIC_BATCH_ANCHORED,
  TOPIC_BATCH_SETTLED,
  TOPIC_WRAP_SETTLED,
  decodeBatchAnchoredLog,
  decodeBatchSettledLog,
  decodeWrapSettledLog,
  fetchMonadSettlementView,
  getLogsChunked,
  readInboxBatchCount,
} from './monadSettlement';

const ROOT = '0x11aa22bb33cc44dd55ee66ff77aa88bb99cc00dd11ee22ff33aa44bb55cc66dd';
const PAD = (n: bigint | number | string): string => {
  const hex = typeof n === 'string' ? n.replace(/^0x/i, '') : BigInt(n).toString(16);
  return `0x${hex.padStart(64, '0')}`;
};

describe('monadSettlement 事件解码', () => {
  it('BatchAnchored：topics[1]=index，data=root‖throughOp（cast 布局）', () => {
    const log = {
      address: MONAD_L1_INBOX,
      topics: [TOPIC_BATCH_ANCHORED, PAD(2)],
      // cast abi-encode 'f(bytes32,uint64)' <ROOT> 7 的产出
      data: `${ROOT.slice(2)}${'07'.padStart(64, '0')}`,
      blockNumber: '0x3f519e5',
    };
    const ev = decodeBatchAnchoredLog(log);
    expect(ev.index).toBe(2n);
    expect(ev.root).toBe(ROOT);
    expect(ev.throughOp).toBe(7n);
    expect(ev.blockNumber).toBe(0x3f519e5);
  });

  it('WrapSettled：topics[1..2] 索引参数，data=fact', () => {
    const programHash = 0x744d16d3n; // 语义示例值（长度形态按 uint256 32B）
    const handBinding = 0xdeadbeefn;
    const fact = 0xcafebabefn;
    const log = {
      address: '0x0000000000000000000000000000000000000001',
      topics: [TOPIC_WRAP_SETTLED, PAD(programHash), PAD(handBinding)],
      data: PAD(fact),
      blockNumber: '0x10',
    };
    const ev = decodeWrapSettledLog(log);
    expect(ev.programHash).toBe(programHash);
    expect(ev.handBinding).toBe(handBinding);
    expect(ev.fact).toBe(fact);
    expect(ev.blockNumber).toBe(0x10);
  });

  it('BatchSettled：operator 地址从 32B topic 恢复 20B 形态', () => {
    const log = {
      topics: [
        TOPIC_BATCH_SETTLED,
        PAD(`0x${'bcd7ecd68d55ca2536f3f50dcbcb44edb0d97aa6'}`),
        PAD(`0x${'ab'.repeat(32)}`),
        PAD(0x42n),
      ],
      data: `${PAD(3).slice(2)}${PAD(96).slice(2)}`,
      blockNumber: '0x20',
    };
    const ev = decodeBatchSettledLog(log);
    expect(ev.operator).toBe('0xbcd7ecd68d55ca2536f3f50dcbcb44edb0d97aa6');
    expect(ev.keccakRoot).toBe(`0x${'ab'.repeat(32)}`);
    expect(ev.programHash).toBe(0x42n);
    expect(ev.proofCount).toBe(3n);
    expect(ev.statementCount).toBe(96n);
  });

  it('topic0 不匹配 → 明确抛错（不静默吞掉异构日志）', () => {
    expect(() =>
      decodeBatchAnchoredLog({ topics: [TOPIC_WRAP_SETTLED, PAD(1)], data: '0x' }),
    ).toThrow(/not a BatchAnchored/);
    expect(() =>
      decodeWrapSettledLog({ topics: [TOPIC_BATCH_ANCHORED, PAD(1)], data: '0x' }),
    ).toThrow(/not a WrapSettled/);
  });
});

describe('monadSettlement 链上读取', () => {
  it('readInboxBatchCount：eth_call batchCount()，实测返回 5 的形态可解析', async () => {
    const calls: Array<{ method: string; params: unknown }> = [];
    const rpc = async (method: string, params?: unknown) => {
      calls.push({ method, params });
      return '0x0000000000000000000000000000000000000000000000000000000000000005';
    };
    await expect(readInboxBatchCount(rpc)).resolves.toBe(5n);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('eth_call');
    const call = (calls[0].params as Array<Record<string, string>>)[0];
    expect(call.to).toBe(MONAD_L1_INBOX);
    expect(call.data).toBe(SELECTOR_BATCH_COUNT);
  });

  it('getLogsChunked：350 块按 100+100+100+50 分片，窗口连续无重叠', async () => {
    const windows: Array<[number, number]> = [];
    const rpc = vi.fn(async (method: string, params?: unknown) => {
      expect(method).toBe('eth_getLogs');
      const f = (params as Array<Record<string, string>>)[0];
      windows.push([Number(BigInt(f.fromBlock)), Number(BigInt(f.toBlock))]);
      return [];
    });
    await getLogsChunked(rpc, { fromBlock: 1000, toBlock: 1349 });
    expect(windows).toEqual([
      [1000, 1099],
      [1100, 1199],
      [1200, 1299],
      [1300, 1349],
    ]);
  });

  it('getLogsChunked：toBlock < fromBlock 直接空、恰 100 块单次拉取', async () => {
    const rpc = vi.fn(async () => [] as unknown[]);
    await expect(getLogsChunked(rpc, { fromBlock: 5, toBlock: 4 })).resolves.toEqual([]);
    await getLogsChunked(rpc, { fromBlock: 5, toBlock: 104 });
    expect(rpc).toHaveBeenCalledTimes(1);
  });

  it('fetchMonadSettlementView：聚合 batchCount + 锚定日志；SettleWrap 未配置时降级', async () => {
    const anchoredLog = {
      address: MONAD_L1_INBOX,
      topics: [TOPIC_BATCH_ANCHORED, PAD(4)],
      data: `${ROOT.slice(2)}${PAD(63).slice(2)}`,
      blockNumber: '0x3f51990',
    };
    const rpc = async (method: string, params?: unknown) => {
      if (method === 'eth_blockNumber') return '0x3f519e5';
      if (method === 'eth_call') {
        return '0x0000000000000000000000000000000000000000000000000000000000000005';
      }
      if (method === 'eth_getLogs') {
        // 模拟"事件在窗口尾部"：只有最后一片返回锚定日志，前面的片返回空
        const f = (params as Array<Record<string, string>>)[0];
        return Number(BigInt(f.toBlock)) === 0x3f519e5 ? [anchoredLog] : [];
      }
      throw new Error(`unexpected ${method}`);
    };
    const view = await fetchMonadSettlementView(rpc, 500);
    expect(view.batchCount).toBe(5n);
    expect(view.headBlock).toBe(0x3f519e5);
    expect(view.anchored).toHaveLength(1);
    expect(view.anchored[0].index).toBe(4n);
    expect(view.anchored[0].throughOp).toBe(63n);
    // 本测试环境未注入 VITE_MONAD_SETTLE_WRAP_ADDRESS → 包裹结算降级为空
    expect(view.settleWrapConfigured).toBe(false);
    expect(view.wrapped).toEqual([]);
  });
});
