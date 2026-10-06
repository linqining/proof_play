// dev/testnet 浏览器联调直签账户（可选配置）。
//
// 两种配置形态：
// - VITE_DEV_ACCOUNT_ADDRESS + VITE_DEV_ACCOUNT_PRIVATE_KEY：单账户；
// - VITE_DEV_ACCOUNTS="addr:pk,addr:pk,…"：多账户（本地 e2e 双人/多人对局
//   用，两个浏览器各选一个）。选择方式（优先级从高到低）：
//     1) URL 查询参数 ?dev=N（1 基，写入 localStorage 后同源会话保持）；
//     2) localStorage 键 zgame_dev_account_idx；
//     3) 默认第 1 个。
//
// 配置后，前端把所选账户当作"已连接钱包"：登录签名（SNIP-12 typed data）、
// 兑换、买入、提现全部用该账户直接签名提交到当前 RPC —— 无需钱包插件即可
// 在浏览器里真实跑通全流程（参考 starkware-libs/starknet-privacy demo 的
// plain Account 用法）。生产环境不配置这些变量，全部回退连接的钱包。
//
// provider 默认块用 PRE_CONFIRMED：测试网/本地节点交易在 accepted 前停留
// pre-confirmed，latest 读 nonce 会拿到过期值（52: Invalid transaction
// nonce）。Sepolia 公共 RPC（publicnode）同样支持 pre_confirmed。

import { Account, RpcProvider, BlockTag, type AccountInterface } from 'starknet';

interface DevAccountEntry {
  address: string;
  privateKey: string;
}

const IDX_STORAGE_KEY = 'zgame_dev_account_idx';

let cachedAccounts: DevAccountEntry[] | null = null;
let cachedSelected: number | null = null;
let cachedAccount: Account | null = null;

function parseDevAccounts(): DevAccountEntry[] {
  if (cachedAccounts) return cachedAccounts;
  const entries: DevAccountEntry[] = [];
  // 多账户形态：逗号分隔的 addr:pk（地址不含 ':'，pk 按 hex/dec 解析也无冒号）
  const list = (import.meta.env.VITE_DEV_ACCOUNTS as string | undefined) ?? '';
  for (const part of list.split(',')) {
    const t = part.trim();
    if (!t) continue;
    const sep = t.lastIndexOf(':');
    if (sep <= 0) continue;
    entries.push({ address: t.slice(0, sep).trim(), privateKey: t.slice(sep + 1).trim() });
  }
  if (entries.length === 0) {
    // 旧单账户形态
    const addr = import.meta.env.VITE_DEV_ACCOUNT_ADDRESS as string | undefined;
    const pk = import.meta.env.VITE_DEV_ACCOUNT_PRIVATE_KEY as string | undefined;
    if (addr && pk) entries.push({ address: addr, privateKey: pk });
  }
  cachedAccounts = entries;
  return entries;
}

/** 解析当前浏览器应使用的账户下标（0 基）：?dev=N > localStorage > 0。 */
function selectedIndex(count: number): number {
  if (cachedSelected !== null) return cachedSelected;
  let idx = 0;
  try {
    const fromUrl = new URLSearchParams(window.location.search).get('dev');
    if (fromUrl && /^\d+$/.test(fromUrl) && Number(fromUrl) >= 1) {
      idx = Number(fromUrl) - 1;
      localStorage.setItem(IDX_STORAGE_KEY, String(idx));
    } else {
      const stored = localStorage.getItem(IDX_STORAGE_KEY);
      if (stored && /^\d+$/.test(stored)) idx = Number(stored);
    }
  } catch {
    // SSR/隐私模式等 localStorage 不可用：退回默认第 1 个
  }
  cachedSelected = Math.min(Math.max(idx, 0), Math.max(count - 1, 0));
  return cachedSelected;
}

export function isDevAccountConfigured(): boolean {
  return parseDevAccounts().length > 0;
}

export function getDevAccountAddress(): string | null {
  const accounts = parseDevAccounts();
  if (accounts.length === 0) return null;
  return accounts[selectedIndex(accounts.length)].address.toLowerCase();
}

export function getDevAccount(): Account | null {
  const accounts = parseDevAccounts();
  if (accounts.length === 0) return null;
  if (!cachedAccount) {
    const entry = accounts[selectedIndex(accounts.length)];
    cachedAccount = new Account({
      provider: new RpcProvider({
        nodeUrl: import.meta.env.VITE_STARKNET_RPC_URL as string,
        blockIdentifier: BlockTag.PRE_CONFIRMED,
      }),
      address: entry.address,
      signer: entry.privateKey,
    });
  }
  return cachedAccount;
}

/**
 * 活跃账户解析（对齐 Cartridge 官方集成模型：Controller 是内嵌 iframe 的
 * passkey 智能钱包，无需浏览器插件；每个浏览器 profile 持有自己的 keychain
 * 账户，多账号联调 = 每个浏览器各自连接自己的 Controller 账户）。
 *
 * 连接的钱包（Cartridge Controller）**优先**——游戏身份必须跟随真实连接的
 * 账户，否则第二个浏览器永远拿不到自己的身份。dev 直签账户只在没有任何
 * 钱包连接时兜底（离线/本地联调）。
 * hook 形态见 hooks/useActiveAccount.ts。
 */
export function activeAddress(connected: string | null | undefined): string | null {
  return (connected ?? null) ?? getDevAccountAddress();
}

export function activeAccount(connected: AccountInterface | null | undefined): AccountInterface | null {
  return (connected ?? null) ?? getDevAccount();
}
