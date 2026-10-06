// STRK20 隐私领取（docs/design/SETTLEMENT_PRIVACY_PLAN.md Part C3 / C5）。
//
// 「领取奖励」两条路径，均通过连接的钱包（Ready / Cartridge）执行：
//
// - 私密领取（首选）：STRK20 Wallet API 两动作模式（transfer amount=OPEN
//   + invoke PokerVaultAnonymizer.privacy_withdraw）。池先把用户屏蔽余额
//   里的 STRK 划给 helper，helper 按额烧毁 vault 筹码，再把等额 STRK 以
//   open note 记回（note owner 隐藏）→ 链上看不出是谁领走了奖励。
//   前提：钱包支持 Wallet API ≥0.10.3（Ready 是官方测试基线），且用户
//   池内屏蔽余额 ≥ 领取额（conservation 在池内闭环）。
// - 公开出金（回退）：vault.withdraw 直提钱包，边缘公开但功能等价。
//
// 能力探测按官方指引只用 `supportedWalletApi` 版本查询（≥0.10.3），绝不
// 用 strk20Balances 之类的数据调用做探测——那会触发钱包授权弹窗。

import { starknetConfig, toWalletFeltHex } from './config';
import { getProvider } from './contracts';
import { logger } from '../helpers/logger';
import type { TxResult } from './starknetGameActions';

const PAYOUT_SECRET_KEY = 'poker.payoutSecret';

/** 读取（或首次生成）本地 payout secret（capability，永不上报）。 */
export function getPayoutSecret(): string | null {
  let secret = localStorage.getItem(PAYOUT_SECRET_KEY);
  if (!secret) {
    const bytes = new Uint8Array(31);
    crypto.getRandomValues(bytes);
    bytes[0] = bytes[0] & 0x0f; // 保证 < 2^251（felt 合法域）
    secret =
      '0x' +
      [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem(PAYOUT_SECRET_KEY, secret);
    logger.log('[strk20] payout secret generated');
  }
  return secret;
}

/** Wallet API 最低版本（STRK20 私密交易 + viewing key 体系）。 */
export const STRK20_WALLET_API_MIN = '0.10.3';

interface Strk20CapableAccount {
  strk20InvokeTransaction?: (actions: unknown[]) => Promise<{ transaction_hash: string }>;
  strk20Balances?: (tokens: string[]) => Promise<Array<{ token: string; balance: bigint }>>;
  supportedWalletApi?: (wallet?: unknown) => Promise<string[]>;
  execute?: (calls: unknown) => Promise<{ transaction_hash: string }>;
  address?: string;
}

/**
 * 获取注入的 STN-1 钱包对象（Ready 安装时即 window.starknet）。
 * STRK20 Wallet API 的私密交易必须经钱包对象（wallet.request）走
 * SNIP-36 证明管线——WalletAccount（starknet-react 连接产物）没有该表面。
 */
export function getInjectedStarknetWallet(): unknown {
  // Ready（argentX）注入的 EIP-6963 命名空间是 starknet_argentX /
  // starknet_ready（starknet-react ensureWallet 同款发现方式），legacy
  // window.starknet 作为兜底。
  const w = globalThis as unknown as Record<string, unknown>;
  return w.starknet_argentX ?? w.starknet_ready ?? w.starknet ?? null;
}

/**
 * Wallet API 请求的统一入口，兼容两类注入形态：
 * - 平铺钱包（Ready/argentX）：request 直接挂在钱包对象上
 * - WSF 钱包（STN-1 标准）：request 收在 features['starknet:walletApi']
 *
 * starknet.js v10 的 walletV6.* / WalletAccount.strk20* 方法内部只认
 * features 表且不判空，对平铺钱包会抛 TypeError（Cannot read properties
 * of undefined (reading 'starknet:walletApi)）——因此这里绝不经由 walletV6，
 * 直接对钱包对象发对应的 request type。
 */
async function walletApiRequest<T = unknown>(
  wallet: Record<string, unknown>,
  type: string,
  params?: unknown,
  timeoutMs = 60000,
): Promise<T> {
  const withTimeout = <X>(p: Promise<X>, ms: number): Promise<X> =>
    Promise.race([
      p,
      new Promise<X>((_, rej) => setTimeout(() => rej(new Error('wallet request timeout')), ms)),
    ]);
  const flat = wallet.request;
  if (typeof flat === 'function') {
    return withTimeout(
      (flat as (c: { type: string; params?: unknown }) => Promise<T>).call(wallet, { type, params }),
      timeoutMs,
    );
  }
  const api = (wallet.features as Record<string, { request?: (c: unknown) => Promise<T> }> | undefined)?.['starknet:walletApi'];
  if (typeof api?.request === 'function') {
    return withTimeout(api.request({ type, params }), timeoutMs);
  }
  throw new Error('wallet has no wallet-api request surface');
}

/**
 * 探测连接钱包是否具备 STRK20 私密交易能力（Wallet API ≥ 0.10.3）。
 * 依次探测：注入钱包对象（supportedWalletApi 版本查询，官方推荐方式）→
 * WalletAccount 方法存在性。绝不用数据类调用做探测（会触发授权弹窗）。
 */
export async function detectStrk20Support(account: unknown): Promise<boolean> {
  // 官方通道优先：get-starknet v6 discovery + WalletAccountV6
  const v6 = await getStrk20WalletAccount();
  if (v6) return true;
  const wallet = getInjectedStarknetWallet() as {
    supportedWalletApi?: () => Promise<string[]>;
    request?: unknown;
    features?: Record<string, unknown>;
  } | null;
  // 注入钱包对象的 supportedWalletApi() 方法（Ready 5.28+ 返回 0.10.x 线；
  // 平铺 request 路由返回的可能是旧 spec 线，两者版本体系不同）
  if (wallet && typeof wallet.supportedWalletApi === 'function') {
    try {
      const versions = await wallet.supportedWalletApi();
      if (
        (versions ?? []).some(
          (v) => typeof v === 'string' && compareVersions(v, STRK20_WALLET_API_MIN) >= 0,
        )
      ) {
        return true;
      }
    } catch (e) {
      logger.warn('[strk20] injected wallet.supportedWalletApi() probe failed:', e);
    }
  }
  if (wallet) {
    try {
      const versions = await walletApiRequest<string[]>(
        wallet,
        'wallet_supportedWalletApi',
        undefined,
        5000,
      );
      if (
        (versions ?? []).some(
          (v) => typeof v === 'string' && compareVersions(v, STRK20_WALLET_API_MIN) >= 0,
        )
      ) {
        return true;
      }
    } catch (e) {
      logger.warn('[strk20] wallet supportedWalletApi probe failed:', e);
    }
  }
  const acct = account as Strk20CapableAccount | null | undefined;
  if (acct && typeof acct.strk20InvokeTransaction === 'function') return true;
  if (acct && typeof acct.supportedWalletApi === 'function') {
    try {
      const versions = await acct.supportedWalletApi();
      if ((versions ?? []).some(
        (v) => typeof v === 'string' && compareVersions(v, STRK20_WALLET_API_MIN) >= 0,
      )) {
        return true;
      }
    } catch (e) {
      logger.warn('[strk20] account supportedWalletApi probe failed:', e);
    }
  }
  // 乐观兜底：注入钱包存在（Ready/argentX 官方私密基线）但版本探测失败
  // （扩展锁定、代理挂起等）时，不再把按钮永久禁用——真实能力在提交时
  // 呈现（claim 失败会带具体错误回显）。
  if (wallet && (typeof wallet.request === 'function' || !!(wallet as { features?: unknown }).features)) {
    logger.log('[strk20] probe inconclusive; injected wallet present — treating as capable');
    return true;
  }
  return false;
}

/**
 * 简单语义化版本比较（'0.10.3' vs '0.9.2' 等；非数字段按 0 处理）。
 * 预发布后缀按 semver 规则处理：'0.10.4-rc.1' < '0.10.4'（若按数字清洗
 * 会变成 0.10.41，连 '0.10.10' 都比不过——版本选择会被预发布线劫持）。
 */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core, pre = ''] = v.trim().split('-');
    const nums = core
      .replace(/[^0-9.]/g, '')
      .split('.')
      .map((n) => parseInt(n, 10) || 0);
    return { nums, pre };
  };
  const A = parse(a);
  const B = parse(b);
  for (let i = 0; i < Math.max(A.nums.length, B.nums.length); i += 1) {
    const diff = (A.nums[i] ?? 0) - (B.nums[i] ?? 0);
    if (diff !== 0) return diff;
  }
  if (A.pre === B.pre) return 0;
  if (!A.pre) return 1;
  if (!B.pre) return -1;
  return A.pre < B.pre ? -1 : 1;
}

/**
 * 钱包错误的统一文本化：钱包 JSON-RPC 错误可能是 Error、裸对象
 * {code, message} 甚至嵌套 data——String() 会得到 '[object Object]'，
 * 导致后面按错误码/错误名的正则全部失配。
 */
export function walletErrText(e: unknown): string {
  if (typeof e === 'string') return e;
  const rec = e as {
    message?: unknown; code?: unknown; data?: unknown; detail?: unknown;
  } | null;
  if (rec && typeof rec === 'object') {
    const parts: string[] = [];
    if (typeof rec.code !== 'undefined') parts.push(`code ${String(rec.code)}`);
    if (typeof rec.message === 'string' && rec.message) parts.push(rec.message);
    if (typeof rec.data === 'string' && rec.data) parts.push(rec.data);
    // 钱包/扩展抛的错误常把原始 payload 挂在非 data 字段：Ready 的
    // PaymasterV2Error 按 SNIP-29 规范把 Avnu 响应整包挂在 .detail
    // （其中 data.execution_error = revert 调用链）——逐个字符串化，
    // 避免弹窗里只剩一行 156 摘要无法归因。
    for (const key of ['data', 'detail'] as const) {
      const v = rec[key];
      if (v && typeof v === 'object') {
        try { parts.push(`${key}: ${JSON.stringify(v)}`); } catch { /* 循环引用等忽略 */ }
      }
    }
    if (parts.length) return parts.join(' ');
    try { return JSON.stringify(e) ?? String(e); } catch { /* fallthrough */ }
  }
  return String((e as Error)?.message ?? e);
}

/**
 * 官方错误码表（types-js wallet-api errors）→ 可操作的中文提示。
 * 返回 null 表示没有映射，调用方原样透出原始错误文本。
 */
function friendlyWalletError(msg: string): string | null {
  const code = Number(/code[":\s]+(\d+)/.exec(msg)?.[1] ?? 0);
  if (code === 118 || /NOT_REGISTERED/i.test(msg)) {
    return '钱包尚未在隐私池注册：请先在 Ready 内做一次 Shield（入池），钱包会自动完成注册，再回来操作。';
  }
  if (code === 119 || /INSUFFICIENT_PRIVATE_BALANCE/i.test(msg)) {
    return '池内屏蔽余额不足：请先在 Ready 内将足额 STRK shield 入池后再试。';
  }
  if (code === 114 || /INVALID_REQUEST_PAYLOAD/i.test(msg)) {
    return (
      '钱包校验 STRK20 请求失败（' + msg.slice(0, 120) +
      '）。多为池内无私密票据（未 shield/未注册）或钱包侧 schema 校验不通过——' +
      '先在 Ready 里 Shield 入池后再试；若已入池仍报此错，把 Console 里 [strk20] 日志发维护者。'
    );
  }
  if (code === 162 || /API_VERSION_NOT_SUPPORTED/i.test(msg)) {
    return (
      '钱包不支持本 dapp 请求的 Wallet API 版本（' + msg.slice(0, 120) +
      '）。请更新 Ready 扩展后重试；若仍报错，把 Console 里 [strk20] 日志发维护者。'
    );
  }
  if (code === 151 || /TOKEN_NOT_SUPPORTED/i.test(msg) || /not supported for private tokens/i.test(msg)) {
    return (
      '钱包当前不对该代币开放私密操作（151 TOKEN_NOT_SUPPORTED）。最常见原因是' +
      '**钱包网络不在 Sepolia**：Ready 重装/更新后默认主网，而本 dapp 是 Sepolia 应用——' +
      '请把 Ready 切到 Sepolia Testnet 后重试。若网络正确仍报此错，说明钱包版本尚未' +
      '对 Sepolia STRK 开放私密代币（钱包内 STRK 资产页也没有 Shield/入池 入口），' +
      '只能等待钱包恢复或换主网验证；并把 Console 里 [strk20] 日志发维护者。'
    );
  }
  if (code === 163 || /UNKNOWN_ERROR/i.test(msg)) {
    return (
      '钱包在处理私密交易时内部失败（163 UNKNOWN_ERROR）。常见于钱包未入池、'
      + '钱包版本变更后的 payload 校验或钱包侧证明服务异常：先在 Ready 内做一次 '
      + 'Shield/入池（钱包会自动完成注册）再回来重试；若已入池仍报此错，'
      + '把 Console 里 [strk20] 日志发维护者。'
    );
  }
  return null;
}

/**
 * 提交用 api_version 的选择。稳定版优先：钱包可能同时声明 shadow-account
 * 预发布线（如 '0.10.4-rc.1'），Ready 对未识别的版本串会回未映射的
 * 163 UNKNOWN_ERROR（2026-09-06 One-click register 线上报错）——预发布
 * 候选只在稳定版失败后作兜底重试。
 */
function pickSubmitApiVersions(
  declared: string[],
): { preferred: string | null; fallback: string | null } {
  const candidates = declared.filter(
    (v) => typeof v === 'string' && compareVersions(v, STRK20_WALLET_API_MIN) >= 0,
  );
  const stable = candidates.filter((v) => !v.includes('-')).sort(compareVersions).pop() ?? null;
  const pre = candidates.filter((v) => v.includes('-')).sort(compareVersions).pop() ?? null;
  if (stable) return { preferred: stable, fallback: pre };
  return { preferred: pre, fallback: null };
}

/**
 * STRK20 actions 的统一提交阶梯（shield/claim 共用）：
 *   1. v6 通道（WalletAccountV6.strk20InvokeTransaction）——不携带
 *      api_version（starknet.js 只发 params:{actions}）；
 *   2. 平铺请求面带稳定版 api_version（历史修复：Ready 5.x 缺它回 114）；
 *   3. 预发布 api_version 兜底重试（稳定版被拒且钱包声明了预发布线时）。
 * v6 通道的 118 NOT_REGISTERED 是终态答复（未入池钱包，平铺重试只会得到
 * 同一个答案），直接原样抛出；其余 v6 失败（包括 163 UNKNOWN_ERROR——
 * 2026-09-06 线上：Ready 5.33.x 对 v6 通道的 payload 校验失败不再回 114）
 * 都降级到平铺通道重试，失败时抛最后一次错误。
 */
async function submitStrk20Actions(
  wallet: Record<string, unknown> | null,
  actions: unknown[],
): Promise<{ transaction_hash?: string }> {
  const declared = await getWalletApiVersions();
  const { preferred, fallback } = pickSubmitApiVersions(declared);
  const v6 = await getStrk20WalletAccount();
  if (v6) {
    try {
      const res = await v6.strk20InvokeTransaction(actions);
      if (res?.transaction_hash) {
        logger.log('[strk20] submitted (V6):', res.transaction_hash);
        return res;
      }
      logger.warn('[strk20] v6 channel returned empty hash; falling back to flat request');
    } catch (err) {
      const msg = walletErrText(err);
      if (/NOT_REGISTERED/i.test(msg)) throw err;
      logger.warn(
        '[strk20] v6 channel rejected (' + msg.slice(0, 120) +
        '); retrying flat request with api_version',
        preferred ?? '(none)',
      );
    }
  }
  try {
    const res = await walletApiRequest<{ transaction_hash?: string }>(
      wallet ?? {},
      'wallet_strk20InvokeTransaction',
      { actions, ...(preferred ? { api_version: preferred } : {}) },
    );
    if (res?.transaction_hash) {
      logger.log('[strk20] submitted (flat, api_version', preferred ?? '(none)', '):', res.transaction_hash);
      return res;
    }
    throw new Error('wallet returned empty tx hash');
  } catch (flatErr) {
    const flatMsg = walletErrText(flatErr);
    if (!fallback || fallback === preferred) throw flatErr;
    logger.warn(
      '[strk20] flat submit failed (' + flatMsg.slice(0, 120) +
      '); retrying with prerelease api_version',
      fallback,
    );
    const res = await walletApiRequest<{ transaction_hash?: string }>(
      wallet ?? {},
      'wallet_strk20InvokeTransaction',
      { actions, api_version: fallback },
    );
    if (res?.transaction_hash) {
      logger.log('[strk20] submitted (flat, prerelease api_version', fallback, '):', res.transaction_hash);
      return res;
    }
    throw new Error('wallet returned empty tx hash');
  }
}

/**
 * 查询连接钱包声明的 Wallet API 版本列表。
 *
 * 关键：Ready/argentX 的注入对象上有 **supportedWalletApi() 方法**（官方
 * 推荐的动态探测入口），它返回的是 Wallet API 0.10.x 线；而 request 路由
 * `wallet_supportedWalletApi` 在平铺面上可能返回旧 spec 线（如 0.7.2），
 * 两者不是一套版本。这里把两条路的结果合并去重，UI 取最大值判断能力。
 */
export async function getWalletApiVersions(): Promise<string[]> {
  const wallet = getInjectedStarknetWallet() as {
    supportedWalletApi?: () => Promise<string[]>;
    request?: unknown;
    features?: Record<string, unknown>;
  } | null;
  const out = new Set<string>();

  // ① 官方推荐：注入钱包对象的 supportedWalletApi() 方法
  if (wallet && typeof wallet.supportedWalletApi === 'function') {
    try {
      const versions = await wallet.supportedWalletApi();
      for (const v of versions ?? []) {
        if (typeof v === 'string') out.add(v);
      }
    } catch (e) {
      logger.warn('[strk20] injected wallet.supportedWalletApi() failed:', e);
    }
  }
  // ② spec request 路由（features 表或 request）
  if (wallet) {
    try {
      const versions = await walletApiRequest<string[]>(
        wallet,
        'wallet_supportedWalletApi',
        undefined,
        5000,
      );
      for (const v of versions ?? []) {
        if (typeof v === 'string') out.add(v);
      }
    } catch (e) {
      logger.warn('[strk20] supportedWalletApi version query failed:', e);
    }
  }
  return [...out];
}

// ------------------------------------------------------------
// WalletAccountV6（官方 STRK20 通道，get-starknet v6 discovery）
// ------------------------------------------------------------

interface Strk20V6Account {
  address: string;
  strk20InvokeTransaction: (actions: unknown[]) => Promise<{ transaction_hash: string }>;
  strk20Balances: (tokens: string[]) => Promise<Array<{ token: string; balance: string | bigint }>>;
  /** starknet ≥10.4 官方干跑：证明 + 池校验但不提交/不经 paymaster。 */
  strk20PrepareInvoke?: (actions: unknown[], simulate: boolean) => Promise<unknown>;
}

let v6AccountPromise: Promise<Strk20V6Account | null> | null = null;

/**
 * 经 get-starknet v6 的 Wallet Standard discovery 拿到 WSF 钱包对象
 * （带 features['starknet:walletApi']），创建官方 WalletAccountV6。
 * 这是 STRK20 私密交易唯一可靠的通道：starknet.js 的 walletV6 或 V6 方法
 * 只认 WSF 钱包；EIP-6963 注入的平铺对象（window.starknet_argentX 等）
 * 没有 features 表，strk20 请求要么 TypeError 要么 INVALID_REQUEST_PAYLOAD。
 */
export async function getStrk20WalletAccount(): Promise<Strk20V6Account | null> {
  if (!v6AccountPromise) {
    v6AccountPromise = (async () => {
      try {
        const [{ createStore }, starknet] = await Promise.all([
          import('@starknet-io/get-starknet-discovery'),
          import('starknet'),
        ]);
        const store = createStore();
        let wallets = store.getWallets();
        if (!wallets.length) {
          // WSF 注册可能晚于首查：等 announce 或 5s 兜底（Ready 异步注册）
          wallets = await new Promise((resolve) => {
            const timer = setTimeout(() => resolve(store.getWallets()), 5000);
            store.subscribe((list) => {
              if (list.length) {
                clearTimeout(timer);
                resolve([...list]);
              }
            });
          });
        }
        if (!wallets.length) {
          logger.log('[strk20] no WSF wallets discovered via store; trying flat-wallet shim');
          // 平铺钱包兜底（Ready ≥5.28.3 声明 0.10.x 线时）：构造最小 WSF 壳
          // （features.request → 平铺 request）接入官方 WalletAccountV6
          const flat = getInjectedStarknetWallet() as {
            supportedWalletApi?: () => Promise<string[]>;
            request?: (call: { type: string; params?: unknown }) => Promise<unknown>;
          } | null;
          if (!flat || typeof flat.request !== 'function') return null;
          let flatVersions: string[] = [];
          if (typeof flat.supportedWalletApi === 'function') {
            try {
              flatVersions = (await flat.supportedWalletApi()) ?? [];
            } catch { /* 探测失败继续走版本外推 */ }
          }
          const supported = flatVersions.some(
            (v) => typeof v === 'string' && compareVersions(v, STRK20_WALLET_API_MIN) >= 0,
          );
          if (!supported) {
            logger.log('[strk20] flat wallet does not declare Wallet API >=', STRK20_WALLET_API_MIN);
            return null;
          }
          const flatRequest = flat.request.bind(flat);
          const request = (call: { type: string; params?: unknown }) => flatRequest(call);
          const shim = {
            name: 'ready',
            version: '0.0.0',
            icon: '',
            features: {
              'starknet:walletApi': { request },
              'standard:events': {
                on: (_event: string, _cb: (x: never) => void) => () => {},
                off: () => {},
              },
              'standard:connect': {
                connect: async ({ silent }: { silent?: boolean } = {}) => {
                  const accounts = (await request({
                    type: 'wallet_requestAccounts',
                    params: { silent_mode: silent },
                  })) as string[];
                  let chainId: string | undefined;
                  try {
                    chainId = (await request({ type: 'wallet_requestChainId' })) as string;
                  } catch { /* 部分实现不提供 */ }
                  return { accounts, chainId };
                },
              },
            },
          };
          const nodeUrl = starknetConfig.rpcUrls[0] ?? starknetConfig.rpcUrl;
          const acc = await starknet.WalletAccountV6.connect(
            { nodeUrl },
            shim as never,
          );
          logger.log('[strk20] WalletAccountV6 connected via flat shim (versions:', flatVersions.join(', '), ')');
          return acc as unknown as Strk20V6Account;
        }
        const picked =
          wallets.find((w) => /ready|argent/i.test(w.name ?? '')) ?? wallets[0];
        const nodeUrl = starknetConfig.rpcUrls[0] ?? starknetConfig.rpcUrl;
        // wallet-standard 6.0.3（starknet 内置）与 6.0.5（discovery 依赖）类型
        // 不可互指——运行时结构一致，此处断言即可
        const acc = await starknet.WalletAccountV6.connect(
          { nodeUrl },
          picked as never,
        );
        logger.log('[strk20] WalletAccountV6 connected via discovery:', picked.name);
        return acc as unknown as Strk20V6Account;
      } catch (e) {
        logger.warn('[strk20] WalletAccountV6 (get-starknet v6) unavailable:', e);
        return null;
      }
    })();
  }
  return v6AccountPromise;
}

/** 查询池内屏蔽余额（钱包会弹授权，仅在用户主动查看余额时调用）。 */
export async function getShieldedBalance(
  account: unknown,
  tokenAddress: string,
): Promise<bigint | null> {
  try {
    // 官方通道：WalletAccountV6.strk20Balances
    const v6 = await getStrk20WalletAccount();
    if (v6) {
      const entries = await v6.strk20Balances([tokenAddress]);
      const norm = tokenAddress.toLowerCase();
      const hit = (entries ?? []).find((e) => BigInt(e.token ?? 0n) === BigInt(norm));
      return hit ? BigInt(hit.balance) : 0n;
    }
  } catch (e) {
    logger.warn('[strk20] v6 shielded balance query failed:', e);
  }
  // 回退：平铺/WSF 统一经 walletApiRequest（绝不走 walletV6.* —— 对平铺钱包必崩）
  const wallet = getInjectedStarknetWallet() as Record<string, unknown> | null;
  if (!wallet) return null;
  try {
    const entries = await walletApiRequest<Array<{ token: string; balance: string | bigint }>>(
      wallet,
      'wallet_strk20Balances',
      { tokens: [tokenAddress] },
    );
    const norm = tokenAddress.toLowerCase();
    const hit = (entries ?? []).find((e) => BigInt(e.token ?? 0n) === BigInt(norm));
    return hit ? BigInt(hit.balance) : 0n;
  } catch (e) {
    logger.warn('[strk20] shielded balance query failed:', e);
    return null;
  }
}

export interface ClaimRewardsArgs {
  /** 领取额（token wei，u256 上限内）。 */
  amountWei: bigint;
}

/**
 * 私密领取奖励（Ready/STRK20 两动作，单笔原子交易）：
 *   1. transfer amount="OPEN" → 开一张 open note（金额在执行时填入）；
 *   2. invoke privacy_withdraw(player, amount(u256), ${openNoteIds[0]})。
 * 池 → helper → 烧筹码 → open note，全在一笔池证明交易里；提交 envelope
 * 与 note owner 都不指向玩家。
 */
/**
 * #隐私池注册辅助：发起一笔**小额 Shield 入池**（公开 deposit）。
 * 钱包隐私引擎处理该动作时会自动生成并登记 viewing key——这是 Ready
 * 118(NOT_REGISTERED) 的官方解法（"先做一次 Shield，钱包会自动完成注册"）。
 * 官方 schema 的 shield 动作只有 {type:'deposit', token, amount} 一种形状
 * （不存在 'shield' 类型；shield 实际是 approve+deposit 两笔，钱包弹两次确认）。
 * 提交管线与 claimRewardsPrivate 完全一致（共用 submitStrk20Actions）：
 * v6 通道 → 平铺带稳定版 api_version 重试 → 预发布版本兜底（v6 通道的
 * 163 UNKNOWN_ERROR 同样触发降级重试——2026-09-06 线上教训）。
 *
 * 已知边界（官方 SDK 文档 sdk/register、setup-requirements）：池注册 = 上链
 * 发布 viewing key，而 viewing key 只存在于钱包内，dapp 无法代注册（
 * SetupRequirement.Register 是硬限制："They must register - you cannot do
 * it for them"）。因此从未入池的钱包对 deposit 直接回 118
 * NOT_REGISTERED——此时返回 notRegistered:true，由 UI 引导用户去钱包内
 * Shield 入池（Ready 的 Shield 会自动完成注册）。
 */
export async function shieldForPoolRegistration(
  account: Strk20CapableAccount | null,
  amountWei: bigint,
): Promise<TxResult & { notRegistered?: boolean }> {
  const wallet = getInjectedStarknetWallet() as Record<string, unknown> | null;
  const acct = account as Strk20CapableAccount | null;
  const hasWalletSurface = !!wallet
    && (typeof (wallet as { request?: unknown }).request === 'function'
      || !!((wallet as { features?: Record<string, unknown> }).features?.['starknet:walletApi']));
  const hasAccountSurface = !!acct?.strk20InvokeTransaction && !!acct.address;
  if (!hasWalletSurface && !hasAccountSurface) {
    return { hash: '', success: false, error: 'Wallet does not support STRK20 private transactions' };
  }
  if (amountWei <= 0n) {
    return { hash: '', success: false, error: 'Amount must be positive' };
  }
  const notRegisteredResult = (): TxResult & { notRegistered?: boolean } => ({
    hash: '',
    success: false,
    notRegistered: true,
    error:
      '池注册需要在 Ready 钱包内完成（viewing key 只保存在钱包中，dapp 无法代注册）：' +
      '打开 Ready → STRK 资产页「Shield / 入池」→ 做一次小额入池（钱包会自动完成注册），' +
      '完成后回到本弹窗点「重新校验」。',
  });
  const { CANONICAL_STRK_ADDRESS } = await import('./starknetGameActions');
  // Ready 的 payload schema 对金额只认规范化 0x 十六进制（十进制字符串直接
  // INVALID_REQUEST_PAYLOAD(114)——与私密领取同一教训，线上实测）。
  const amountHex = '0x' + amountWei.toString(16);
  const actions = [{ type: 'deposit', token: CANONICAL_STRK_ADDRESS, amount: amountHex }];
  // 提交走统一阶梯：v6 通道 → 平铺带稳定版 api_version → 预发布版本兜底
  // （v6 通道的 163 UNKNOWN_ERROR 也会降级重试——2026-09-06 线上教训）。
  try {
    const res = await submitStrk20Actions(wallet, actions);
    const hash = res?.transaction_hash ?? '';
    if (!hash) return { hash: '', success: false, error: 'wallet returned empty tx hash' };
    logger.log('[strk20] pool-registration shield submitted:', hash);
    return { hash, success: true };
  } catch (e) {
    const msg = walletErrText(e);
    logger.warn('[strk20] pool-registration shield submit failed:', msg);
    // 118：从未入池的钱包不能 deposit——唯一出路是钱包内 Shield（自动注册）
    if (/NOT_REGISTERED/i.test(msg)) return notRegisteredResult();
    const friendly = friendlyWalletError(msg);
    if (friendly) return { hash: '', success: false, error: friendly };
    throw e;
  }
}

export async function claimRewardsPrivate(
  account: unknown,
  args: ClaimRewardsArgs,
): Promise<TxResult> {
  const wallet = getInjectedStarknetWallet() as Record<string, unknown> | null;
  const { anonymizerAddress } = starknetConfig.privacy;
  const acct = account as Strk20CapableAccount | null;
  const hasWalletSurface = !!wallet
    && (typeof (wallet as { request?: unknown }).request === 'function'
      || !!((wallet as { features?: Record<string, unknown> }).features?.['starknet:walletApi']));
  const hasAccountSurface = !!acct?.strk20InvokeTransaction && !!acct.address;
  if (!hasWalletSurface && !hasAccountSurface) {
    return { hash: '', success: false, error: 'Wallet does not support STRK20 private transactions' };
  }
  if (!acct?.address) {
    return { hash: '', success: false, error: 'Connected account address unavailable' };
  }
  if (!anonymizerAddress) {
    return { hash: '', success: false, error: 'PokerVaultAnonymizer address not configured' };
  }
  const amount = args.amountWei;
  if (amount <= 0n) {
    return { hash: '', success: false, error: 'Amount must be positive' };
  }
  // Ready 的 payload schema 对 felt 只认规范化 0x 十六进制
  // （^0x(0|[a-fA-F1-9]{1}[a-fA-F0-9]{0,62})$，0 必须是 '0x0'），十进制字符串
  // 直接 INVALID_REQUEST_PAYLOAD(114)——线上实测；u256 拆 lo/hi 都转 hex。
  // 2026-09-07 主网实测补充：带前导零的地址（0x01fa…/0x00cb…）同样被 schema
  // 拒绝，player/recipient/lo/hi 一律走 toWalletFeltHex 规范化。
  const lo = toWalletFeltHex(amount & 0xffffffffffffffffffffffffffffffffn);
  const hi = toWalletFeltHex(amount >> 128n);
  const player = toWalletFeltHex(acct.address);
  // 隐私池内流转的资产是原生 STRK（pSTRK/PokerToken 已弃用——官方 Sepolia
  // 隐私池面向 STRK，钱包侧对未入池 token 直接拒绝 INVALID_REQUEST_PAYLOAD）
  const { CANONICAL_STRK_ADDRESS } = await import('./starknetGameActions');
  const actions = [
    // 阶段 5：开输出 open note（金额在执行时由 helper 的出资填入）。
    {
      type: 'transfer',
      token: CANONICAL_STRK_ADDRESS,
      amount: 'OPEN',
      recipient: player,
    },
    // 阶段 7：anonymizer 守恒出金（2026-09-07 修复）：withdraw_to 烧掉
    // player 的等额筹码并把 vault 背书 STRK 释放给 helper，helper 全额
    // 记回上面的 open note——输出由 vault 出资，无需池内预存余额。
    // 旧模型（burn_chips + 用户 withdraw 自筹注资）每领 X 销毁 X 价值，
    // 已废弃。calldata 与 helper privacy_invoke(operation, player,
    // amount:u256, note_id) 对齐；operation=1 = OP_WITHDRAW，felt 均 0x hex。
    {
      type: 'invoke',
      contract: anonymizerAddress,
      calldata: ['0x1', player, lo, hi, '${openNoteIds[0]}'],
    },
  ];
  try {
    // 提交走统一阶梯：v6 通道 → 平铺带稳定版 api_version → 预发布版本兜底
    // （v6 通道的 163 UNKNOWN_ERROR 也会降级重试——2026-09-06 线上教训）。
    const res = await submitStrk20Actions(wallet, actions);
    const hash = res?.transaction_hash ?? '';
    if (!hash) return { hash: '', success: false, error: 'wallet returned empty tx hash' };
    logger.log('[strk20] private claim submitted:', hash);
    return { hash, success: true };
  } catch (err) {
    logger.error('[strk20] private claim failed:', err);
    // 按官方错误码表归因（types-js wallet-api errors）：118 未注册 /
    // 119 屏蔽余额不足 / 114 schema 校验失败 / 162 api_version 不支持 /
    // 163 钱包内部失败（映射与文案统一在 friendlyWalletError）。
    const msg = walletErrText(err);
    // paymaster 类失败（如 Avnu 156 TRANSACTION_EXECUTION_ERROR）只有一行
    // 摘要、不上链、查不到 revert。用钱包官方干跑（strk20PrepareInvoke，
    // 完成证明 + 池校验但不提交、不经 paymaster）二分定位：
    //   干跑也失败 → 钱包/池层拒绝（错误文本即根因）；
    //   干跑通过   → 合约/池/证明全正常，失败在 paymaster 提交层（找 Avnu/Ready）。
    if (/paymaster|\b156\b|TRANSACTION_EXECUTION_ERROR/i.test(msg)) {
      try {
        const v6 = await getStrk20WalletAccount();
        const prepare = v6?.strk20PrepareInvoke;
        if (typeof prepare === 'function') {
          await prepare.call(v6, actions, true);
          const diag =
            '干跑（证明+池校验，不经 paymaster）通过 → 合约/池/证明均正常，' +
            '失败发生在 paymaster 提交层（Avnu/Ready 侧），请附带本条日志向钱包/Avnu 反馈。';
          logger.warn('[strk20] private claim dry-run:', diag);
          return { hash: '', success: false, error: `${friendlyWalletError(msg) ?? msg} ｜ ${diag}` };
        }
      } catch (pe) {
        const pmsg = walletErrText(pe);
        const diag = `干跑（不经 paymaster）复现失败 → 钱包/池层拒绝，根因：${pmsg.slice(0, 300)}`;
        logger.warn('[strk20] private claim dry-run:', diag);
        return { hash: '', success: false, error: `${friendlyWalletError(msg) ?? msg} ｜ ${diag}` };
      }
    }
    return { hash: '', success: false, error: friendlyWalletError(msg) ?? msg };
  }
}

/**
 * 公开出金回退：vault.withdraw 直提钱包地址（边缘公开）。
 * Cartridge session policy 已预授权 withdraw；Ready 会弹一次确认。
 */
export async function claimRewardsPublic(
  account: unknown,
  args: ClaimRewardsArgs,
): Promise<TxResult> {
  const acct = account as Strk20CapableAccount | null;
  if (!acct?.execute || !acct.address) {
    return { hash: '', success: false, error: 'Wallet account unavailable' };
  }
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) {
    return { hash: '', success: false, error: 'PokerVault address not configured' };
  }
  const amount = args.amountWei;
  if (amount <= 0n) {
    return { hash: '', success: false, error: 'Amount must be positive' };
  }
  const lo = (amount & 0xffffffffffffffffffffffffffffffffn).toString();
  const hi = (amount >> 128n).toString();
  try {
    const res = await acct.execute({
      contractAddress: pokerVaultAddress,
      entrypoint: 'withdraw',
      calldata: [lo, hi],
    });
    const hash = res.transaction_hash;
    // 出金到账以交易落地为准；中继提交（paymaster）时哈希可能延迟可见。
    getProvider()
      .waitForTransaction(hash)
      .catch(() => logger.warn('[strk20] public withdraw receipt not visible yet:', hash));
    return { hash, success: true };
  } catch (err) {
    logger.error('[strk20] public withdraw failed:', err);
    return { hash: '', success: false, error: String(err) };
  }
}

/**
 * Part A Phase 1：注册赔付承诺（vault.register_payout_commitment）。
 * commitment = poseidon(secret)，secret 本地生成/保存——链上只见承诺。
 * 注册后，赢家在该手结算时即可从认领托管私密领取。
 * 返回 'registered'（已有）/ 'tx'（已提交注册交易）。
 */
/**
 * 查询玩家是否已在 vault 注册 payout commitment（链上真值）。
 * 返回 commitment 的 felt 值（0 = 未注册）。
 */
/**
 * #33 在局锁定：读玩家在 vault 的锁定筹码（wei，u128）。
 * 锁定部分不可领取/出金（burn_chips/withdraw 断言 spendable），离桌后
 * 由 operator 结算续钟、TTL（默认 12h）后可无许可自助解锁。
 * 查询失败返回 null（调用方按 0 处理）。
 */
export async function getVaultLockedBalanceWei(account: unknown): Promise<bigint | null> {
  const acct = account as { address?: string } | null;
  if (!acct?.address) return null;
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) return null;
  try {
    const s = await import('starknet');
    const provider = getProvider();
    const selector = '0x' + s.hash.starknetKeccak('locked_balance').toString(16);
    const res = await provider.callContract({
      contractAddress: pokerVaultAddress,
      entrypoint: 'locked_balance',
      calldata: [acct.address],
    });
    const lo = BigInt(res[0] ?? 0);
    const hi = BigInt(res[1] ?? 0);
    return lo + (hi << 128n);
  } catch (e) {
    logger.warn('[strk20] locked_balance read failed:', e);
    return null;
  }
}

/** #33 在局锁定的会话信息（vault view 聚合）：锁定量 + 解锁截止时间。 */
export interface VaultLockSession {
  lockedWei: bigint;
  /** 解锁截止（unix 秒）= session_last_activity + lock_ttl；0 = 无会话。 */
  unlockDeadlineSec: number;
}

export async function getVaultLockSession(account: unknown): Promise<VaultLockSession | null> {
  const acct = account as { address?: string } | null;
  if (!acct?.address) return null;
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) return null;
  try {
    const provider = getProvider();
    // 带参（玩家地址）与无参（lock_ttl 是全局配置 view）分开传——
    // 给无参 view 传 calldata 会 Contract error，整个会话读取退化为
    // null → 前端锁定行消失且按全额发交易撞 in-hand lock（2026-09-07）。
    const callAddr = async (entrypoint: string): Promise<string[]> =>
      await provider.callContract({ contractAddress: pokerVaultAddress, entrypoint, calldata: [acct.address!] });
    const callNoArg = async (entrypoint: string): Promise<string[]> =>
      await provider.callContract({ contractAddress: pokerVaultAddress, entrypoint, calldata: [] });
    const [locked, lastActivityRes, ttlRes] = await Promise.all([
      callAddr('locked_balance'),
      callAddr('session_last_activity'),
      callNoArg('lock_ttl'),
    ]);
    const lo = BigInt(locked[0] ?? 0);
    const hi = BigInt(locked[1] ?? 0);
    const lastActivity = Number(BigInt(lastActivityRes[0] ?? 0));
    const ttl = Number(BigInt(ttlRes[0] ?? 0));
    return {
      lockedWei: lo + (hi << 128n),
      unlockDeadlineSec: lastActivity > 0 && ttl > 0 ? lastActivity + ttl : 0,
    };
  } catch (e) {
    logger.warn('[strk20] lock session read failed:', e);
    return null;
  }
}

/**
 * #33 到期自助解锁（无许可，任何人可调）：TTL 过期后解除锁定。
 * 前端在锁定到期时提供入口；成功后 locked 清零即可全额领取。
 */
export async function unlockVaultAfterDeadline(account: unknown): Promise<TxResult> {
  const acct = account as Strk20CapableAccount | null;
  if (!acct?.execute || !acct.address) {
    return { hash: '', success: false, error: 'Wallet account unavailable' };
  }
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) {
    return { hash: '', success: false, error: 'PokerVault address not configured' };
  }
  try {
    const res = await acct.execute({
      contractAddress: pokerVaultAddress,
      entrypoint: 'unlock_after_deadline',
      calldata: [acct.address],
    });
    const hash = res.transaction_hash;
    getProvider()
      .waitForTransaction(hash)
      .then(() => logger.log('[strk20] unlock_after_deadline confirmed:', hash))
      .catch(() => logger.warn('[strk20] unlock receipt not visible yet:', hash));
    return { hash, success: true };
  } catch (err) {
    logger.error('[strk20] unlock_after_deadline failed:', err);
    return { hash: '', success: false, error: String(err) };
  }
}

export async function getRegisteredPayoutCommitment(
  account: unknown,
): Promise<string | null> {
  const acct = account as { address?: string } | null;
  if (!acct?.address) return null;
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) return null;
  try {
    const s = await import('starknet');
    const provider = getProvider();
    const selector = '0x' + s.hash.starknetKeccak('payout_commitment').toString(16);
    const res = await provider.callContract({
      contractAddress: pokerVaultAddress,
      entrypoint: 'payout_commitment',
      calldata: [acct.address],
    });
    const v = BigInt(res[0] ?? 0);
    return v !== 0n ? '0x' + v.toString(16) : null;
  } catch (e) {
    logger.warn('[strk20] payout_commitment read failed:', e);
    return null;
  }
}

export async function ensurePayoutCommitment(account: unknown): Promise<
  { status: 'registered' | 'tx' } | { status: 'error'; error: string }
> {
  const acct = account as {
    address?: string;
    execute?: (calls: unknown) => Promise<{ transaction_hash: string }>;
  } | null;
  if (!acct?.execute || !acct.address) {
    return { status: 'error', error: 'wallet account unavailable' };
  }
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) {
    return { status: 'error', error: 'PokerVault address not configured' };
  }
  const secret = getPayoutSecret();
  if (!secret) return { status: 'error', error: 'cannot generate payout secret' };
  // 与合约 corelib Poseidon 同规范（单元素 H(x)）
  const s = await import('starknet');
  const commitment: string = '0x' + BigInt(
    s.hash.computePoseidonHashOnElements([secret]),
  ).toString(16);
  // 已注册则无需重复上链
  const provider = getProvider();
  const selector = await (async () => {
    const k = (s as unknown as { hash: { starknetKeccak: (n: string) => bigint } }).hash;
    return k ? k.starknetKeccak('payout_commitment') : null;
  })();
  if (selector) {
    try {
      const res = await (provider as unknown as {
        callContract: (c: unknown) => Promise<{ result: string[] }>;
      }).callContract({
        contractAddress: pokerVaultAddress,
        // starknet.js v10 只认 entrypoint（字符串或 felt）；旧字段名
        // entryPointSelector 会被忽略并回退默认 selector → RPC 报
        // "Requested entry point does not exist"（线上复现）。
        entrypoint: 'payout_commitment',
        calldata: [acct.address],
      });
      // v10 callContract 直接返回 string[]（非 {result} 包装），两者都兼容
      const raw: string | undefined = Array.isArray(res)
        ? (res as unknown as string[])[0]
        : res?.result?.[0];
      if (raw && BigInt(raw) !== 0n) {
        return { status: 'registered' };
      }
    } catch (e) {
      logger.warn('[strk20] payout_commitment read failed (continuing to register):', e);
    }
  }
  const res = await acct.execute({
    contractAddress: pokerVaultAddress,
    entrypoint: 'register_payout_commitment',
    calldata: [commitment],
  });
  logger.log('[strk20] payout commitment registered, tx:', res.transaction_hash);
  return { status: 'tx' };
}
