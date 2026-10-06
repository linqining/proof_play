// =============================================================================
// monadSettlement.ts — Monad 测试网结算状态读取（SettleWrap / L1Inbox）
//
// 读取两条链上事实源（只读，不写链）：
//   1) SettleWrap.WrapSettled —— 单手 STARK→Groth16 包裹结算
//      （contracts/monad/src/SettleWrap.sol:27：
//        event WrapSettled(uint256 indexed programHash,
//                          uint256 indexed handBinding, uint256 fact)）。
//      ※ 侦察口径订正：任务书里的"HandWrapSettlement"事件在合约里不存在，
//        单手结算事件的真实名字是 WrapSettled，按真实合约接入。
//   2) L1Inbox.BatchAnchored —— L2 批次根锚定
//      （contracts/monad/src/L1Inbox.sol:78：
//        event BatchAnchored(uint64 indexed index, bytes32 root,
//                            uint64 throughOp)）。
//
// 零依赖：事件 topic0 由 cast sig-event 离线计算后硬编码（本会话实测），
// 日志解码手写 ABI 规则；不引入 viem/ethers。
//
// 实测约束（2026-09-28 testnet-rpc.monad.xyz）：
//   - eth_getLogs 单次窗口 ≤ 100 块（超出报 -32614），拉取按 ≤100 块分片；
//   - chainId 0x279f，batchCount() 选择子 0x06f13056，实测返回 5。
// =============================================================================

import type { Eip1193Provider } from './monadWallet';

/** 9-27 部署的 L1Inbox（环境事实给定地址；batchCount() 实测 = 5）。 */
export const MONAD_L1_INBOX = '0x60ecddd1359356a43a69de84a1cf235a69a30e71';

/**
 * SettleWrap 合约地址：不在 9-27 已部署三件套（Inbox/Outbox/Bridge）里，
 * 由 scripts/deploy_wrap_monad.sh 单独部署 → 走 env 注入；未配置时
 * 包裹结算读取自动降级为空（不报错，Inbox 锚定照常展示）。
 */
export const MONAD_SETTLE_WRAP_ADDRESS: string | null =
  (import.meta.env.VITE_MONAD_SETTLE_WRAP_ADDRESS as string | undefined) ?? null;

/** keccak("BatchAnchored(uint64,bytes32,uint64)")（cast sig-event 实测）。 */
export const TOPIC_BATCH_ANCHORED =
  '0xfdbe3de9a44396bb3ab8a6384d4d1c800968e59edb52369bc27f88b93d98ff48';
/** keccak("WrapSettled(uint256,uint256,uint256)")（cast sig-event 实测）。 */
export const TOPIC_WRAP_SETTLED =
  '0x7018a142f33c2f6224e87cb72ead7fe76e6f752f05a71d15129a812c106cbdc1';
/** keccak("BatchSettled(address,bytes32,uint256,uint256,uint256)")（同上）。 */
export const TOPIC_BATCH_SETTLED =
  '0xaeef9128e03865a79399da95987584fe052c94570898c859358548c635ceaa4d';

/** batchCount() 选择子（cast sig 'batchCount()' = 0x06f13056）。 */
export const SELECTOR_BATCH_COUNT = '0x06f13056';

/** 节点对 eth_getLogs 的单次窗口上限（实测 -32614: limited to a 100 range）。 */
export const MAX_GETLOGS_RANGE = 100;
/** 默认回看窗口（块）。Monad 测试网 ~0.5s/块 → 1000 块 ≈ 8 分钟。 */
export const DEFAULT_LOOKBACK_BLOCKS = 1000;

/** 最小 JSON-RPC 面：EIP-1193 provider 或 fetchMonadRpc 的返回值都满足。 */
export type RpcCaller = (
  method: string,
  params?: unknown[] | Record<string, unknown>,
) => Promise<unknown>;

/** 直连公共 RPC 的 fetch 工厂（结算面板在未连接钱包时也能读链）。 */
export function fetchMonadRpc(url: string = 'https://testnet-rpc.monad.xyz'): RpcCaller {
  return async (method, params) => {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params ?? [] }),
    });
    if (!resp.ok) throw new Error(`rpc ${method}: http ${resp.status}`);
    const body = (await resp.json()) as { result?: unknown; error?: { message?: string } };
    if (body.error) throw new Error(`rpc ${method}: ${body.error.message ?? 'unknown'}`);
    return body.result;
  };
}

/** 从 EIP-1193 provider 取 RpcCaller（钱包已连接场景，无 CORS 疑虑）。 */
export function providerAsRpc(p: Eip1193Provider): RpcCaller {
  return (method, params) => p.request({ method, params });
}

// ---------------------------------------------------------------------------
// 纯解码器（ABI 规则手写，单测向量经 cast abi-encode 交叉验证）
// ---------------------------------------------------------------------------

export interface BatchAnchoredEvent {
  index: bigint;
  root: string;
  throughOp: bigint;
  blockNumber: number;
}

export interface WrapSettledEvent {
  programHash: bigint;
  handBinding: bigint;
  fact: bigint;
  blockNumber: number;
}

export interface BatchSettledEvent {
  operator: string;
  keccakRoot: string;
  programHash: bigint;
  proofCount: bigint;
  statementCount: bigint;
  blockNumber: number;
}

interface RawLogLike {
  address?: unknown;
  topics?: unknown;
  data?: unknown;
  blockNumber?: unknown;
}

function logTopics(log: RawLogLike): string[] {
  return Array.isArray(log.topics) ? (log.topics as string[]) : [];
}

function logData(log: RawLogLike): string {
  return typeof log.data === 'string' ? log.data : '0x';
}

function logBlock(log: RawLogLike): number {
  if (typeof log.blockNumber !== 'string') return 0;
  return Number(/^0x/i.test(log.blockNumber) ? BigInt(log.blockNumber) : log.blockNumber);
}

function topicHex(topic: string): string {
  const bare = topic.replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(bare)) throw new Error(`bad 32-byte topic: ${topic}`);
  return bare;
}

function dataWord(data: string, wordIndex: number): bigint {
  const bare = data.replace(/^0x/i, '').toLowerCase();
  const word = bare.slice(wordIndex * 64, wordIndex * 64 + 64);
  if (word.length < 64) throw new Error(`data word ${wordIndex} missing: ${data}`);
  return BigInt(`0x${word}`);
}

function wordHex(data: string, wordIndex: number): string {
  const bare = data.replace(/^0x/i, '').toLowerCase();
  const word = bare.slice(wordIndex * 64, wordIndex * 64 + 64);
  if (word.length < 64) throw new Error(`data word ${wordIndex} missing: ${data}`);
  return `0x${word}`;
}

/** BatchAnchored(uint64 indexed index, bytes32 root, uint64 throughOp) 解码：
 *  topics[1] = index；data = root(32B) ‖ throughOp(32B)。 */
export function decodeBatchAnchoredLog(log: RawLogLike): BatchAnchoredEvent {
  const topics = logTopics(log);
  if ((topics[0] ?? '').toLowerCase() !== TOPIC_BATCH_ANCHORED) {
    throw new Error('not a BatchAnchored log');
  }
  return {
    index: BigInt(`0x${topicHex(topics[1] ?? '0x')}`),
    root: wordHex(logData(log), 0),
    throughOp: dataWord(logData(log), 1),
    blockNumber: logBlock(log),
  };
}

/** WrapSettled(uint256 indexed programHash, uint256 indexed handBinding,
 *  uint256 fact) 解码：topics[1..2] 索引参数；data = fact(32B)。 */
export function decodeWrapSettledLog(log: RawLogLike): WrapSettledEvent {
  const topics = logTopics(log);
  if ((topics[0] ?? '').toLowerCase() !== TOPIC_WRAP_SETTLED) {
    throw new Error('not a WrapSettled log');
  }
  return {
    programHash: BigInt(`0x${topicHex(topics[1] ?? '0x')}`),
    handBinding: BigInt(`0x${topicHex(topics[2] ?? '0x')}`),
    fact: dataWord(logData(log), 0),
    blockNumber: logBlock(log),
  };
}

/** BatchSettled(address indexed operator, bytes32 indexed keccakRoot,
 *  uint256 indexed programHash, uint256 proofCount, uint256 statementCount)
 *  解码：topics[1..3] 索引参数；data = proofCount ‖ statementCount。 */
export function decodeBatchSettledLog(log: RawLogLike): BatchSettledEvent {
  const topics = logTopics(log);
  if ((topics[0] ?? '').toLowerCase() !== TOPIC_BATCH_SETTLED) {
    throw new Error('not a BatchSettled log');
  }
  const addr = BigInt(`0x${topicHex(topics[1] ?? '0x')}`).toString(16).padStart(40, '0');
  return {
    operator: `0x${addr}`,
    keccakRoot: wordHex(`0x${topicHex(topics[2] ?? '0x')}`, 0),
    programHash: BigInt(`0x${topicHex(topics[3] ?? '0x')}`),
    proofCount: dataWord(logData(log), 0),
    statementCount: dataWord(logData(log), 1),
    blockNumber: logBlock(log),
  };
}

// ---------------------------------------------------------------------------
// 链上读取（窗口分片 ≤ 100 块）
// ---------------------------------------------------------------------------

/** L1Inbox 当前已折叠批次根数量（batchCount()）。 */
export async function readInboxBatchCount(rpc: RpcCaller): Promise<bigint> {
  const v = await rpc('eth_call', [
    { to: MONAD_L1_INBOX, data: SELECTOR_BATCH_COUNT },
    'latest',
  ]);
  if (typeof v !== 'string') throw new Error('batchCount: unexpected eth_call result');
  return BigInt(v);
}

interface GetLogsFilter {
  fromBlock: number;
  toBlock: number;
  address?: string;
  topic0?: string;
}

async function getLogs(rpc: RpcCaller, filter: GetLogsFilter): Promise<RawLogLike[]> {
  const params: Record<string, unknown> = {
    fromBlock: `0x${filter.fromBlock.toString(16)}`,
    toBlock: `0x${filter.toBlock.toString(16)}`,
  };
  if (filter.address) params.address = filter.address;
  if (filter.topic0) params.topics = [filter.topic0];
  const v = await rpc('eth_getLogs', [params]);
  return Array.isArray(v) ? (v as RawLogLike[]) : [];
}

/** 分片拉取 [fromBlock, toBlock] 的指定事件（每片 ≤100 块，顺序回放）。 */
export async function getLogsChunked(
  rpc: RpcCaller,
  filter: GetLogsFilter,
): Promise<RawLogLike[]> {
  if (filter.toBlock < filter.fromBlock) return [];
  const out: RawLogLike[] = [];
  let cursor = filter.fromBlock;
  while (cursor <= filter.toBlock) {
    const end = Math.min(cursor + MAX_GETLOGS_RANGE - 1, filter.toBlock);
    out.push(...(await getLogs(rpc, { ...filter, fromBlock: cursor, toBlock: end })));
    cursor = end + 1;
  }
  return out;
}

/** L1Inbox 最近的 BatchAnchored 批次锚定。 */
export async function fetchRecentBatchAnchored(
  rpc: RpcCaller,
  lookbackBlocks = DEFAULT_LOOKBACK_BLOCKS,
): Promise<BatchAnchoredEvent[]> {
  const head = Number(
    BigInt((await rpc('eth_blockNumber')) as string),
  );
  const from = Math.max(0, head - lookbackBlocks);
  const logs = await getLogsChunked(rpc, {
    fromBlock: from,
    toBlock: head,
    address: MONAD_L1_INBOX,
    topic0: TOPIC_BATCH_ANCHORED,
  });
  return logs.map(decodeBatchAnchoredLog);
}

/**
 * SettleWrap 最近的 WrapSettled 单手结算。
 * 未配置 MONAD_SETTLE_WRAP_ADDRESS 时降级为空数组（读不到≠没结算）。
 */
export async function fetchRecentWrapSettled(
  rpc: RpcCaller,
  lookbackBlocks = DEFAULT_LOOKBACK_BLOCKS,
): Promise<WrapSettledEvent[]> {
  if (!MONAD_SETTLE_WRAP_ADDRESS) return [];
  const head = Number(BigInt((await rpc('eth_blockNumber')) as string));
  const from = Math.max(0, head - lookbackBlocks);
  const logs = await getLogsChunked(rpc, {
    fromBlock: from,
    toBlock: head,
    address: MONAD_SETTLE_WRAP_ADDRESS,
    topic0: TOPIC_WRAP_SETTLED,
  });
  return logs.map(decodeWrapSettledLog);
}

/** 结算面板聚合视图：锚定进度 + 包裹结算明细。 */
export interface MonadSettlementView {
  batchCount: bigint;
  headBlock: number;
  anchored: BatchAnchoredEvent[];
  wrapped: WrapSettledEvent[];
  settleWrapConfigured: boolean;
}

/** 一次性拉取结算状态（供 React 面板/调试页调用）。 */
export async function fetchMonadSettlementView(
  rpc: RpcCaller,
  lookbackBlocks = DEFAULT_LOOKBACK_BLOCKS,
): Promise<MonadSettlementView> {
  const head = Number(BigInt((await rpc('eth_blockNumber')) as string));
  const batchCount = await readInboxBatchCount(rpc);
  const from = Math.max(0, head - lookbackBlocks);
  const [anchoredLogs, wrapped] = await Promise.all([
    getLogsChunked(rpc, {
      fromBlock: from,
      toBlock: head,
      address: MONAD_L1_INBOX,
      topic0: TOPIC_BATCH_ANCHORED,
    }),
    fetchRecentWrapSettled(rpc, lookbackBlocks),
  ]);
  return {
    batchCount,
    headBlock: head,
    anchored: anchoredLogs.map(decodeBatchAnchoredLog),
    wrapped,
    settleWrapConfigured: MONAD_SETTLE_WRAP_ADDRESS !== null,
  };
}
