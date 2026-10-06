// =============================================================================
// monadWallet.ts — Monad 钱包（EIP-1193 window.ethereum）连接器
//
// 与 zchainWallet.ts（window.zchain 独立命名空间）平行的第三方 provider
// 接入：走标准 EIP-1193 注入 provider（MetaMask/Rabby 等任何实现），
// 不引入 viem/ethers，零新依赖。
//
//   1) 连接：wallet_switchEthereumChain → 不在钱包里则 wallet_addEthereumChain
//      （Monad 测试网 chainId 10143 = 0x279f）→ eth_requestAccounts；
//   2) 余额：eth_getBalance（MON，18 位小数）；
//   3) 转账/交易：eth_sendTransaction，按 Monad 测试网实测的计费模型
//      （按 gas_limit×price 计费而非 used——zchain/monad-settlement
//      src/bin/monad_hand_gas.rs 头注 2026-09-27 实测）先 eth_estimateGas
//      再把 limit 提到 est×1.1，gasPrice 取节点建议价；
//   4) 登录签名：personal_sign（EIP-191），摘要见 evmKeccak.personalMessageHash。
//
// 会话状态存 localStorage（monadAddress），供 useAuth 判定"当前身份来自
// Monad 钱包"，与 ZChain 会话同款：无 Starknet account，跳过 STRK 余额查询。
// 私钥永远不进本前端——地址由注入钱包派生（eth_requestAccounts）。
// =============================================================================

import { keccak256Utf8, personalMessageHash } from './evmKeccak';
import { logger } from '../helpers/logger';
import { WEI_PER_CHIP } from '../clientConfig';

/** EIP-1193 provider 的最小形状（本页只用到 request）。 */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>;
  isMetaMask?: boolean;
}

/** Monad 测试网参数（chainId 10143；主网 143 = 0x8f 预留，暂不接入）。 */
export const MONAD_TESTNET_CHAIN_ID_DEC = 10143;
export const MONAD_TESTNET_CHAIN_ID_HEX = '0x279f';
export const MONAD_TESTNET_RPC_URL = 'https://testnet-rpc.monad.xyz';
/** 预留：Monad 主网（本仓库暂不接入，只作文档常量防误用）。 */
export const MONAD_MAINNET_CHAIN_ID_DEC = 143;
export const MONAD_MAINNET_CHAIN_ID_HEX = '0x8f';

/** wallet_addEthereumChain 的链描述（不带 blockExplorerUrls——未核实的
 *  浏览器地址不写入配置）。 */
export const MONAD_TESTNET_CHAIN_PARAMS = {
  chainId: MONAD_TESTNET_CHAIN_ID_HEX,
  chainName: 'Monad Testnet',
  nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
  rpcUrls: [MONAD_TESTNET_RPC_URL],
} as const;

/**
 * gas 紧 limit 安全系数：limit = estimate × 11 / 10 + 1（向上取整）。
 * Monad 按 limit 计费，这是唯一杠杆，宁小勿大——与部署脚本
 * scripts/deploy_wrap_monad.sh（est×11//10+1）和
 * zchain/monad-settlement LIMIT_HEADROOM{NUM,DEN}=11/10 同口径。
 */
export const GAS_LIMIT_HEADROOM_NUM = 11n;
export const GAS_LIMIT_HEADROOM_DEN = 10n;

const MONAD_ADDR_KEY = 'monadAddress';

/** 回执轮询：1s × 60（MonadBFT 单槽终结，正常数秒内打包）。 */
const RECEIPT_POLL_MS = 1000;
const RECEIPT_MAX_ATTEMPTS = 60;

/** eth_getTransactionReceipt 中我们关心的子集。 */
export interface MonadReceipt {
  /** 0x1 成功。 */
  status: '0x1' | '0x0';
  transactionHash: string;
  blockNumber: number;
  /** 实际消耗 gas（展示用；Monad 扣费按 limit 计，见文件头注）。 */
  gasUsed: bigint | null;
  effectiveGasPrice: bigint | null;
  logs: Array<{ address: string; topics: string[]; data: string }>;
}

interface RawReceiptLog {
  address?: unknown;
  topics?: unknown;
  data?: unknown;
}

// ---------------------------------------------------------------------------
// 纯函数助手（单测覆盖面：地址派生 / 数量编码 / tx 参数编码）
// ---------------------------------------------------------------------------

/** 规范化 EVM 地址：非法（非 0x + 40 hex）→ null；合法 → 小写 0x 形式。 */
export function normalizeEvmAddress(input: string): string | null {
  if (typeof input !== 'string') return null;
  const m = /^0x([0-9a-fA-F]{40})$/.exec(input.trim());
  return m ? `0x${m[1].toLowerCase()}` : null;
}

/**
 * EIP-55 校验和地址派生：小写 hex 逐字符按 keccak(小写地址) 高位 nibble
 * 决定大小写。纯本地计算，用于统一展示形态（钱包返回大小写不一）。
 * Throws 非法地址。
 */
export function toEip55Address(input: string): string {
  const lower = normalizeEvmAddress(input);
  if (!lower) throw new Error(`invalid EVM address: ${input}`);
  // EIP-55：哈希输入是 40 字符裸 hex（不含 0x 前缀）
  const hash = keccak256Utf8(lower.slice(2));
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    const ch = lower[2 + i];
    // hash 的第 i 个 nibble（从高位数）决定第 i 个字母是否大写
    const nibble = parseInt(hash[2 + i], 16);
    out += /[a-f]/.test(ch) && nibble >= 8 ? ch.toUpperCase() : ch;
  }
  return out;
}

/** 数字 → 0x 数量编码（EIP-1193 quantity；0 → '0x0'，无前导零）。 */
export function toHexQuantity(value: bigint): string {
  if (value < 0n) throw new Error(`negative quantity: ${value}`);
  return `0x${value.toString(16)}`;
}

/** 0x 数量 → bigint（'0x' 缺省按十进制宽容解析失败即抛）。 */
export function fromHexQuantity(value: unknown): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`invalid hex quantity: ${String(value)}`);
  }
  return BigInt(value);
}

/** MON（18 位小数）金额 → wei bigint。支持 '0.01' / '1.5' 形式。 */
export function parseEtherToWei(amount: string): bigint {
  const m = /^(\d+)(?:\.(\d{1,18}))?$/.exec(amount.trim());
  if (!m) throw new Error(`invalid ether amount: ${amount}`);
  const whole = BigInt(m[1]) * 10n ** 18n;
  if (m[2] === undefined) return whole;
  return whole + (BigInt(m[2]) * 10n ** BigInt(18 - m[2].length));
}

/** wei → 可读 MON 字符串（固定 precision 位小数，截断不四舍五入）。 */
export function formatWeiToEther(wei: bigint, precision = 6): string {
  const base = 10n ** 18n;
  const whole = wei / base;
  const frac = (wei % base).toString().padStart(18, '0').slice(0, precision);
  return `${whole}.${frac}`;
}

/** eth_sendTransaction 的交易意图（value/data 可选，gas/gasPrice 由
 *  buildMonadTxParams 按 Monad 计费纪律填充）。 */
export interface MonadTxIntent {
  to?: string;
  value?: bigint;
  data?: string;
}

/**
 * Monad tx 参数编码：gas = ceil(est × 11/10) + 1，gasPrice 原样。
 * 纯函数——单测直接覆盖（计费模型见文件头注）。
 */
export function buildMonadTxParams(
  estimatedGas: bigint,
  gasPriceWei: bigint,
  intent: MonadTxIntent = {},
): Record<string, string> {
  if (estimatedGas <= 0n) throw new Error(`bad gas estimate: ${estimatedGas}`);
  if (gasPriceWei <= 0n) throw new Error(`bad gas price: ${gasPriceWei}`);
  const gas = (estimatedGas * GAS_LIMIT_HEADROOM_NUM) / GAS_LIMIT_HEADROOM_DEN + 1n;
  const params: Record<string, string> = {
    gas: toHexQuantity(gas),
    gasPrice: toHexQuantity(gasPriceWei),
  };
  if (intent.to !== undefined) params.to = normalizeEvmAddress(intent.to) ?? intent.to;
  if (intent.value !== undefined) params.value = toHexQuantity(intent.value);
  if (intent.data !== undefined) params.data = intent.data;
  return params;
}

// ---------------------------------------------------------------------------
// provider 连接器（与 zchainWallet 同款会话语义）
// ---------------------------------------------------------------------------

/** 页面是否运行在带 EIP-1193 注入钱包的浏览器里（Monad 入口可用性）。 */
export function isMonadProvider(): boolean {
  const p = (window as { ethereum?: unknown }).ethereum as
    | Partial<Eip1193Provider>
    | undefined;
  return typeof p?.request === 'function';
}

/** 当前身份是否来自 Monad 钱包（本会话已连接）。 */
export function isMonadSession(): boolean {
  try {
    return localStorage.getItem(MONAD_ADDR_KEY) !== null;
  } catch {
    return false;
  }
}

/** 当前 Monad 会话的账户地址（EIP-55 校验和形式），未连接返回 null。 */
export function monadAddress(): string | null {
  try {
    return localStorage.getItem(MONAD_ADDR_KEY);
  } catch {
    return null;
  }
}

export function clearMonadSession(): void {
  try {
    localStorage.removeItem(MONAD_ADDR_KEY);
  } catch {
    /* ignore */
  }
}

function provider(): Eip1193Provider {
  const p = (window as { ethereum?: Eip1193Provider }).ethereum;
  if (!p || typeof p.request !== 'function') {
    throw new Error('Monad wallet not installed (no EIP-1193 window.ethereum)');
  }
  return p;
}

async function ensureMonadChain(p: Eip1193Provider): Promise<void> {
  try {
    await p.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: MONAD_TESTNET_CHAIN_ID_HEX }],
    });
    return;
  } catch (e) {
    // 4902 = 钱包未收录该链 → 走添加流程；其余错误上抛（用户拒绝等）。
    const code = (e as { code?: number }).code;
    if (code !== 4902 && code !== -32603) throw e;
  }
  await p.request({ method: 'wallet_addEthereumChain', params: [MONAD_TESTNET_CHAIN_PARAMS] });
}

async function requestChainId(p: Eip1193Provider): Promise<string> {
  const v = await p.request({ method: 'eth_chainId' });
  if (typeof v !== 'string') throw new Error('eth_chainId: unexpected response');
  return v.toLowerCase();
}

/**
 * 连接 Monad 钱包：切/加链 → eth_requestAccounts（钱包弹窗派生地址）→
 * 校验落网 chainId == 10143 → 写入本地会话（EIP-55 校验和形式）。
 */
export async function monadConnect(): Promise<string> {
  const p = provider();
  await ensureMonadChain(p);
  const chainId = await requestChainId(p);
  if (chainId !== MONAD_TESTNET_CHAIN_ID_HEX) {
    throw new Error(
      `wrong network: wallet on chain ${chainId}, expected ${MONAD_TESTNET_CHAIN_ID_HEX} (Monad Testnet)`,
    );
  }
  const res = await p.request({ method: 'eth_requestAccounts' });
  const first = Array.isArray(res) ? res[0] : undefined;
  const addr = normalizeEvmAddress(typeof first === 'string' ? first : '');
  if (!addr) throw new Error('Monad wallet: no account authorized');
  const checksummed = toEip55Address(addr);
  localStorage.setItem(MONAD_ADDR_KEY, checksummed);
  logger.log('[Monad] connected:', checksummed);
  return checksummed;
}

/** 账户原生余额（wei，latest）。 */
export async function monadGetBalance(address: string): Promise<bigint> {
  const p = provider();
  const v = await p.request({
    method: 'eth_getBalance',
    params: [normalizeEvmAddress(address) ?? address, 'latest'],
  });
  return fromHexQuantity(v);
}

/** 节点建议 gasPrice（wei；测试网 ~102 gwei）。 */
export async function monadGasPrice(): Promise<bigint> {
  const p = provider();
  return fromHexQuantity(await p.request({ method: 'eth_gasPrice' }));
}

/** eth_estimateGas（真实执行 gas 估计； Monad 扣费按 limit，见头注）。 */
export async function monadEstimateGas(intent: MonadTxIntent): Promise<bigint> {
  const p = provider();
  const tx: Record<string, string> = {};
  if (intent.to !== undefined) tx.to = normalizeEvmAddress(intent.to) ?? intent.to;
  if (intent.value !== undefined) tx.value = toHexQuantity(intent.value);
  if (intent.data !== undefined) tx.data = intent.data;
  return fromHexQuantity(await p.request({ method: 'eth_estimateGas', params: [tx] }));
}

function parseReceipt(raw: unknown): MonadReceipt {
  const r = raw as {
    status?: unknown;
    transactionHash?: unknown;
    blockNumber?: unknown;
    gasUsed?: unknown;
    effectiveGasPrice?: unknown;
    logs?: unknown;
  };
  if (typeof r.status !== 'string' || (r.status !== '0x1' && r.status !== '0x0')) {
    throw new Error(`receipt: bad status ${String(r.status)}`);
  }
  if (typeof r.transactionHash !== 'string') {
    throw new Error('receipt: missing transactionHash');
  }
  const logs: MonadReceipt['logs'] = Array.isArray(r.logs)
    ? (r.logs as RawReceiptLog[]).map((l) => ({
        address: typeof l.address === 'string' ? l.address : '',
        topics: Array.isArray(l.topics) ? (l.topics as string[]) : [],
        data: typeof l.data === 'string' ? l.data : '0x',
      }))
    : [];
  return {
    status: r.status,
    transactionHash: r.transactionHash,
    blockNumber: Number(fromHexQuantity(r.blockNumber ?? '0x0')),
    gasUsed: typeof r.gasUsed === 'string' ? fromHexQuantity(r.gasUsed) : null,
    effectiveGasPrice:
      typeof r.effectiveGasPrice === 'string' ? fromHexQuantity(r.effectiveGasPrice) : null,
    logs,
  };
}

/**
 * 转账/交易发送（Monad 计费纪律全流程）：
 * eth_estimateGas → limit = est×1.1 + 1 → eth_gasPrice → eth_sendTransaction
 * （钱包弹窗签名）→ 轮询回执。返回结算回执供 UI 展示。
 */
export async function monadSendTransaction(intent: MonadTxIntent): Promise<MonadReceipt> {
  const p = provider();
  const est = await monadEstimateGas(intent);
  const gasPrice = await monadGasPrice();
  const params = buildMonadTxParams(est, gasPrice, intent);
  logger.log('[Monad] send tx:', { ...params, est: est.toString() });
  const hash = await p.request({ method: 'eth_sendTransaction', params: [params] });
  if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`send: bad tx hash ${String(hash)}`);
  }
  for (let attempt = 0; attempt < RECEIPT_MAX_ATTEMPTS; attempt++) {
    const raw = await p.request({
      method: 'eth_getTransactionReceipt',
      params: [hash],
    });
    if (raw !== null && raw !== undefined) return parseReceipt(raw);
    await new Promise((r) => setTimeout(r, RECEIPT_POLL_MS));
  }
  throw new Error(`tx ${hash} not mined within ${RECEIPT_MAX_ATTEMPTS}s`);
}

/**
 * 登录签名：personal_sign（EIP-191，钱包弹窗确认）。返回签名 (r,s,v) 65B hex；
 * 摘要用 evmKeccak.personalMessageHash 本地复算（与服务端核对一致）。
 */
export async function monadPersonalSign(address: string, message: string): Promise<string> {
  const p = provider();
  const sig = await p.request({
    method: 'personal_sign',
    params: [
      `0x${Array.from(new TextEncoder().encode(message), (b) =>
        b.toString(16).padStart(2, '0'),
      ).join('')}`,
      normalizeEvmAddress(address) ?? address,
    ],
  });
  if (typeof sig !== 'string' || !/^0x[0-9a-fA-F]+$/.test(sig)) {
    throw new Error('personal_sign: unexpected response');
  }
  return sig;
}

/** 本地复算 personal_sign 消息摘要（登录凭证 messageHash 用）。 */
export function monadLoginMessageHash(message: string): string {
  return personalMessageHash(message);
}

// ---------------------------------------------------------------------------
// L1Bridge 买入（chips ← MON 锁仓；合约：contracts/monad/src/L1Bridge.sol）
// ---------------------------------------------------------------------------

/** L1Bridge 地址（VITE_MONAD_L1BRIDGE_ADDRESS；未配置返回 null——UI 据此禁用链上买入）。 */
export function monadL1BridgeAddress(): string | null {
  const addr = (import.meta.env.VITE_MONAD_L1BRIDGE_ADDRESS as string | undefined)?.trim();
  if (!addr) return null;
  return normalizeEvmAddress(addr) ?? addr;
}

/** `depositNative(address)` calldata（selector + 左补零 32B 地址）。 */
export function depositNativeCalldata(to: string): string {
  // keccak256Utf8 返回带 0x 前缀——先剥再截 4 字节 selector。
  const selector = keccak256Utf8('depositNative(address)').replace(/^0x/, '').slice(0, 8);
  const padded = (normalizeEvmAddress(to) ?? to).replace(/^0x/, '').toLowerCase().padStart(64, '0');
  return `0x${selector}${padded}`;
}

/**
 * 链上买入：向 `L1Bridge.depositNative(自己)` 锁 `chips × WEI_PER_CHIP` wei
 * 的 MON（与 Starknet PokerVault.deposit 同语义的 Monad 替换件）。返回结算
 * 回执；`transactionHash` 随 SIT_DOWN_V2 上送，服务端核验回执 + DepositInitiated
 * 事件后由存款桥铸 appchain note（chips 即到账）。
 */
export async function monadBuyInDeposit(chips: number, player?: string): Promise<MonadReceipt> {
  const bridge = monadL1BridgeAddress();
  if (!bridge) throw new Error('L1Bridge 未配置（VITE_MONAD_L1BRIDGE_ADDRESS）');
  const addr = player ?? monadAddress();
  if (!addr) throw new Error('Monad 会话未连接');
  const receipt = await monadSendTransaction({
    to: bridge,
    value: BigInt(Math.round(chips)) * WEI_PER_CHIP,
    data: depositNativeCalldata(addr),
  });
  if (receipt.status !== '0x1') {
    throw new Error(`L1Bridge deposit reverted (tx ${receipt.transactionHash})`);
  }
  return receipt;
}
