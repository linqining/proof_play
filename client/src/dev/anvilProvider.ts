// =============================================================================
// anvilProvider.ts — 本地 Monad 买入联调的 EIP-1193 代理（dev-only）
//
// 设置 VITE_DEV_ANVIL_RPC（本地 anvil JSON-RPC，`anvil --chain-id 10143`）后，
// 在无任何注入钱包的浏览器里把 `window.ethereum` 指向 anvil：登录
// personal_sign、余额、L1Bridge.depositNative 的 eth_sendTransaction 全部走
// 真实 EVM 交易（anvil 预置解锁账户由节点代签）。真钱包（MetaMask/Rabby）
// 注入时本代理让位——它只做离线兜底，测试网联调仍走真钱包。
// =============================================================================

const RPC_URL = import.meta.env.VITE_DEV_ANVIL_RPC as string | undefined;
// anvil 预置账户 #0（默认解锁、预资），可用 VITE_DEV_ANVIL_ACCOUNT 覆盖。
const DEFAULT_ACCOUNT = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

const FORWARDABLE = new Set([
  'eth_chainId',
  'eth_accounts',
  'eth_getBalance',
  'eth_estimateGas',
  'eth_gasPrice',
  'eth_sendTransaction',
  'eth_getTransactionReceipt',
  'eth_getLogs',
  'eth_call',
  'eth_blockNumber',
  // 登录路径（anvil 对解锁账户代签 personal_sign）。
  'personal_sign',
]);

/** 安装 dev anvil 代理。返回是否安装（未配置/非 dev/已有真钱包 → false）。 */
export function installDevAnvilProvider(): boolean {
  if (!RPC_URL || !import.meta.env.DEV) return false;
  const w = window as Window & { ethereum?: unknown };
  if (w.ethereum) return false;
  const account =
    ((import.meta.env.VITE_DEV_ANVIL_ACCOUNT as string | undefined) ?? '').trim() ||
    DEFAULT_ACCOUNT;
  w.ethereum = {
    isAnvil: true,
    request: async ({
      method,
      params,
    }: {
      method: string;
      params?: unknown[] | Record<string, unknown>;
    }): Promise<unknown> => {
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') {
        return [account];
      }
      if (!FORWARDABLE.has(method)) return null;
      // anvil 对解锁账户代签，但 eth_sendTransaction 必须显式带 from；
      // eth_estimateGas / eth_call 缺省 from 会落零地址（无余额 → OutOfFunds）。
      let p = params;
      if (method === 'eth_sendTransaction' || method === 'eth_estimateGas' || method === 'eth_call') {
        const tx = Array.isArray(params) ? { ...(params[0] as Record<string, unknown>) } : {};
        if (!tx.from) tx.from = account;
        p = [tx];
      }
      const res = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params: p }),
      });
      const json = (await res.json()) as {
        result?: unknown;
        error?: { message?: string };
      };
      if (json.error) {
        throw new Error(`anvil rpc ${method}: ${json.error.message ?? 'unknown error'}`);
      }
      return json.result ?? null;
    },
    on: () => {},
    removeListener: () => {},
  };
  // eslint-disable-next-line no-console
  console.info(`[dev-anvil] window.ethereum → ${RPC_URL} (account ${account})`);
  return true;
}
