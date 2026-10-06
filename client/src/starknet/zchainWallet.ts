// =============================================================================
// zchainWallet.ts — ProofPlay Wallet（window.zchain）连接器
//
// 通过 ZChain 浏览器钱包扩展注入的 window.zchain provider（独立命名空间，
// 非 EIP-1193 / Starknet injected）完成：
//   1) 连接（requestAccounts → tagged pubkey hex33 账户地址）；
//   2) 登录签名（transfer 自转 1 单位 PLAY 的结构化操作，扩展弹窗显式
//      确认后返回 wallet-core 重算的确认摘要 digest）；
//   3) 买入签名（buy_in 结构化操作：tableId + seatOwner）。
//
// 会话状态存 localStorage（zchainAddress），供 useAuth / useGameActions /
// Seat 判定"当前身份来自 ZChain 钱包"，从而跳过 Starknet 链上买入路径
// （服务端 dev 结算模式下买入不入账，结算走 appchain 出口提交 zchain）。
// =============================================================================

import { logger } from '../helpers/logger';

/** window.zchain provider（inpage.js 注入形状的最小子集）。 */
interface ZChainProvider {
  isZChain: boolean;
  providerName: string;
  requestAccounts: () => Promise<unknown>;
  getAccounts: () => Promise<{ accounts: string[]; locked?: boolean }>;
  signOperation: (operation: Record<string, unknown>, previewHash: string) => Promise<ZChainSignResult>;
  getNotes?: (filter?: Record<string, unknown>) => Promise<Array<Record<string, unknown>>>;
}

export interface ZChainSignResult {
  /** wallet-core 确认摘要（hex）。 */
  digest: string;
  /** 操作 borsh 编码（hex）。 */
  operationBorsh: string;
  preview: unknown;
}

const ZCHAIN_ADDR_KEY = 'zchainAddress';

/** 页面是否运行在装了 ZChain 钱包的浏览器里。 */
export function isZChainProvider(): boolean {
  return typeof (window as { zchain?: unknown }).zchain === 'object'
    && (window as { zchain?: { isZChain?: boolean } }).zchain?.isZChain === true;
}

/** 当前身份是否来自 ZChain 钱包（本会话已连接）。 */
export function isZChainSession(): boolean {
  try {
    return localStorage.getItem(ZCHAIN_ADDR_KEY) !== null;
  } catch {
    return false;
  }
}

/** 当前 ZChain 会话的账户地址（tagged pubkey hex33），未连接返回 null。 */
export function zchainAddress(): string | null {
  try {
    return localStorage.getItem(ZCHAIN_ADDR_KEY);
  } catch {
    return null;
  }
}

export function clearZChainSession(): void {
  try {
    localStorage.removeItem(ZCHAIN_ADDR_KEY);
  } catch {
    /* ignore */
  }
}

function provider(): ZChainProvider {
  const p = (window as { zchain?: ZChainProvider }).zchain;
  if (!p || p.isZChain !== true) {
    throw new Error('ProofPlay Wallet not installed');
  }
  return p;
}

/**
 * 连接 ZChain 钱包：扩展弹窗显式确认后返回账户地址（tagged pubkey hex33），
 * 并写入本地会话状态。
 */
export async function zchainConnect(): Promise<string> {
  const p = provider();
  const res = await p.requestAccounts() as { accounts?: string[]; address?: string };
  const addr = res?.accounts?.[0] ?? res?.address ?? null;
  if (!addr || typeof addr !== 'string') {
    throw new Error('ProofPlay Wallet: no account (locked or rejected)');
  }
  localStorage.setItem(ZCHAIN_ADDR_KEY, addr);
  logger.log('[ZChain] connected:', addr);
  return addr;
}

/** 归一化 hex：去 0x 前缀 + 小写（扩展校验只收裸 hex 字符）。 */
function normHex(v: string): string {
  const s = v.toLowerCase().replace(/^0x/, '');
  return /^[0-9a-f]*$/.test(s) ? s : v;
}

/** 收集 spendable note 承诺与总面额（登录/买入签名的输入）。 */
async function collectInputs(p: ZChainProvider): Promise<{ inputs: string[]; total: bigint }> {
  let notes: Array<Record<string, unknown>> = [];
  try {
    notes = (await p.getNotes?.({ spendable: true })) ?? [];
  } catch (e) {
    logger.warn('[ZChain] getNotes failed:', e);
  }
  const inputs: string[] = [];
  let total = 0n;
  for (const n of notes) {
    if (n.spendable !== true) continue;
    const c = String(n.commitment ?? '').toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{64}$/.test(c)) continue;
    inputs.push(c);
    try {
      const amt = BigInt(String(n.amount ?? '0'));
      if (amt > 0n) total += amt;
    } catch { /* 非法金额忽略该 note 的面额 */ }
  }
  return { inputs, total };
}

/**
 * 登录签名：transfer 全额自转（wallet-core 强制守恒 outputs == inputs），
 * 扩展弹窗显式确认后返回确认摘要。无可用 note 时明确报错（先在弹窗
 * devnet 水龙头铸造 PLAY note）。
 */
export async function zchainSignLogin(addr: string): Promise<string> {
  const p = provider();
  const { inputs, total } = await collectInputs(p);
  if (inputs.length === 0 || total === 0n) {
    throw Object.assign(
      new Error('no spendable PLAY note — 请先在 ProofPlay Wallet 弹窗的 devnet 水龙头铸造'),
      { code: 'NoPlayableNote' },
    );
  }
  const op = {
    kind: 'transfer',
    assetClass: 'PLAY',
    chainId: 'zchain-devnet-1',
    domain: 'zchain',
    abiVersion: 1,
    nonce: Date.now(),
    expiry: Math.floor(Date.now() / 1000) + 300,
    inputs,
    outputs: [{ owner: normHex(addr), amount: total.toString() }],
  };
  const res = await p.signOperation(op, '');
  logger.log('[ZChain] login signed, digest:', res.digest);
  return res.digest;
}

/**
 * 买入签名：buy_in 结构化操作（tableId + seatOwner），扩展弹窗显式确认，
 * 返回确认摘要（作为 SIT_DOWN_V2 的链下买入凭证传给服务端）。
 */
export async function zchainSignBuyIn(addr: string, tableId: number): Promise<string> {
  const p = provider();
  const { inputs } = await collectInputs(p);
  if (inputs.length === 0) {
    throw Object.assign(
      new Error('no spendable PLAY note — 请先在 ProofPlay Wallet 弹窗的 devnet 水龙头铸造'),
      { code: 'NoPlayableNote' },
    );
  }
  const op = {
    kind: 'buy_in',
    assetClass: 'PLAY',
    chainId: 'zchain-devnet-1',
    domain: 'zchain',
    abiVersion: 1,
    nonce: Date.now(),
    expiry: Math.floor(Date.now() / 1000) + 300,
    inputs,
    tableId,
    seatOwner: normHex(addr),
  };
  const res = await p.signOperation(op, '');
  logger.log('[ZChain] buy_in signed for table', tableId, 'digest:', res.digest);
  return res.digest;
}
