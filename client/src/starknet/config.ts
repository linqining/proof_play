// Starknet configuration for the zgame frontend.
//
// Addresses default to the canonical Sepolia STRK20 token and the local test
// vault/settlement from poker_texas_air/poker_contracts. Override via
// VITE_POKER_VAULT_ADDRESS / VITE_POKER_SETTLEMENT_ADDRESS for production.
//
// Plan C（执行层加固）新增两组配置：
// - 多 RPC failover：VITE_STARKNET_RPC_URLS（逗号分隔，按优先级排序）；
//   未设置时退化为 [VITE_STARKNET_RPC_URL] + 链内置公共端点。
// - paymaster 中继：默认走同源 /api/starknet/paymaster（game server 注入
//   x-api-key 后透传给上游 paymaster），VITE_PAYMASTER_DISABLED=true 可强制
//   全部交易走 session key 直签。

import { STRK20_SEPOLIA_ADDRESS } from './abis';

export const STRK_DECIMALS = 18;

/** 1 chip = 1e15 wei of STRK（0.001 STRK）。与 texas 服务端
 *  starknet::config::WEI_PER_CHIP 及买入弹窗 "1 STRK = 1,000 chips" 一致
 *  （pSTRK/swap 已下线，筹码直接锚定原生 STRK）。 */
export const WEI_PER_CHIP = 1_000_000_000_000_000n;

/** 1 STRK = 1_000 chips. */
export const CHIPS_PER_STRK = 1_000;

/** 筹码数 → STRK 显示文本（4 位小数）。与 ClaimRewardsModal 的换算一致。 */
export const chipsToStrkText = (chips: number): string =>
  (Number(BigInt(Math.max(0, Math.floor(chips))) * WEI_PER_CHIP) / 1e18).toFixed(4);

// 公共端点黑名单记录：Blast API 已于 2026-09 停服（starknet-sepolia/
// starknet-mainnet.public.blastapi.io 一律 403 "no longer available"，
// 且无 CORS 头——浏览器侧表现为 preflight CORS 报错 + failover 熔断被
// 污染）。1rpc/nethermind-free/lava/thirdweb/redefine 当前均不收无钥
// starknet 流量；需要第二节点时在 VITE_STARKNET_RPC_URLS 里自行加
// 私有端点（如 Alchemy）。
const DEFAULT_SEPOLIA_RPCS = [
  'https://starknet-sepolia-rpc.publicnode.com',
];
const DEFAULT_MAINNET_RPCS = [
  'https://starknet-rpc.publicnode.com',
];

const MAINNET_CHAIN_ID = '0x534e5f4d41494e';

/** Plan C paymaster 中继通道配置。 */
export interface PaymasterRelayConfig {
  /** true = 跳过中继，全部直签（线上紧急开关）。 */
  disabled: boolean;
  /** sponsored = 平台代付 gas；default = 用户以 gasToken 支付。 */
  feeMode: 'sponsored' | 'default';
  /** feeMode=default 时的 gas token 地址（ERC-20）。 */
  gasToken: string;
  /** 服务端中继端点（JSON-RPC 透传，服务端注入 x-api-key）。 */
  relayUrl: string;
  /** 能力探测端点（GET，返回 {configured: boolean}）。 */
  statusUrl: string;
}

/**
 * Plan B 私密买入（STRK20 privacy pool + PokerVaultAnonymizer）。
 * wallet-api 后端就绪（enabled + 池 + anonymizer 地址）即启用；否则买入
 * 自动走公开路径（Plan C paymaster/直签）。SDK 后端还需 proving/discovery URL。
 */
export interface PrivacyBuyInConfig {
  /** 总开关（VITE_PRIVACY_BUYIN_ENABLED）。默认 false = 公开路径。 */
  enabled: boolean;
  /** Plan D P2.2：私密出金开关（VITE_UNSHIELD_ENABLED）。 */
  unshieldEnabled: boolean;
  /** STRK20 privacy pool 合约地址（VITE_STRK20_POOL_ADDRESS）。 */
  poolAddress: string;
  /** PokerVaultAnonymizer 合约地址（VITE_POKER_VAULT_ANONYMIZER_ADDRESS）。 */
  anonymizerAddress: string;
  /** 上游 proving service URL（VITE_PRIVACY_PROVING_URL）。 */
  provingUrl: string;
  /** discovery service URL（VITE_PRIVACY_DISCOVERY_URL）。 */
  discoveryUrl: string;
}

export interface StarknetConfig {
  /** Starknet chain id in starknet.js hex form (SN_SEPOLIA / SN_MAIN). */
  chainId: '0x534e5f5345504f4c4941' | '0x534e5f4d41494e';
  /** 主 RPC（兼容旧配置读取；实际请求走 rpcUrls failover 列表）。 */
  rpcUrl: string;
  /** 多 RPC 端点（failover 顺序即优先级，去重后至少 1 个）。 */
  rpcUrls: string[];
  strk20Address: string;
  /** PokerSwap 合约（固定 1 STRK = 1000 pSTRK）。未配置时兑换入口隐藏。 */
  /** @deprecated pSTRK/swap 已下线，仅为旧 env 兼容保留读取。 */
  swapAddress: string;
  pokerVaultAddress: string;
  pokerSettlementAddress: string;
  paymaster: PaymasterRelayConfig;
  privacy: PrivacyBuyInConfig;
}

function readEnv(key: string, fallback: string): string {
  const v = (import.meta as unknown as { env: Record<string, string | undefined> }).env[key];
  return v && v.length > 0 ? v : fallback;
}

function readBool(key: string): boolean {
  const v = (import.meta as unknown as { env: Record<string, string | undefined> }).env[key];
  return v === 'true' || v === '1';
}

function buildRpcUrls(chainId: string): string[] {
  const listed = readEnv('VITE_STARKNET_RPC_URLS', '');
  if (listed) {
    const urls = listed
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (urls.length > 0) return [...new Set(urls)];
  }
  const primary = readEnv(
    'VITE_STARKNET_RPC_URL',
    chainId === MAINNET_CHAIN_ID ? DEFAULT_MAINNET_RPCS[0] : DEFAULT_SEPOLIA_RPCS[0],
  );
  const fallbacks =
    chainId === MAINNET_CHAIN_ID ? DEFAULT_MAINNET_RPCS : DEFAULT_SEPOLIA_RPCS;
  return [...new Set([primary, ...fallbacks.filter((u) => u !== primary)])];
}

/**
 * STRK20 Wallet API 的 felt 规范化：去前导零的 0x hex（0 → '0x0'）。
 * 钱包 schema（^0x(0|[a-fA-F1-9][a-fA-F0-9]{0,62})$）会拒绝
 * '0x01fa…' 这类前导零形式和 '0x' 空 hex（INVALID_REQUEST_PAYLOAD 114）；
 * 地址、u256 lo/hi 进入 payload 前都必须过这一层。
 */
export function toWalletFeltHex(v: bigint | string): string {
  const b = typeof v === 'bigint' ? v : BigInt(v);
  return '0x' + b.toString(16);
}

const chainId = readEnv(
  'VITE_STARKNET_CHAIN_ID',
  '0x534e5f5345504f4c4941',
) as '0x534e5f5345504f4c4941' | '0x534e5f4d41494e';

export const starknetConfig: StarknetConfig = {
  chainId,
  rpcUrl: readEnv(
    'VITE_STARKNET_RPC_URL',
    chainId === MAINNET_CHAIN_ID ? DEFAULT_MAINNET_RPCS[0] : DEFAULT_SEPOLIA_RPCS[0],
  ),
  rpcUrls: buildRpcUrls(chainId),
  strk20Address: readEnv('VITE_STRK_TOKEN_ADDRESS', STRK20_SEPOLIA_ADDRESS),
  swapAddress: readEnv('VITE_POKER_SWAP_ADDRESS', ''),
  pokerVaultAddress: readEnv('VITE_POKER_VAULT_ADDRESS', ''),
  pokerSettlementAddress: readEnv('VITE_POKER_SETTLEMENT_ADDRESS', ''),
  paymaster: {
    disabled: readBool('VITE_PAYMASTER_DISABLED'),
    feeMode: readEnv('VITE_PAYMASTER_FEE_MODE', 'sponsored') === 'default' ? 'default' : 'sponsored',
    gasToken: readEnv('VITE_PAYMASTER_GAS_TOKEN', ''),
    relayUrl: readEnv('VITE_PAYMASTER_RELAY_URL', '/api/starknet/paymaster'),
        // httpClient baseURL 已含 /api；statusUrl 相对该 base，避免 /api/api 双前缀
    statusUrl: readEnv('VITE_PAYMASTER_STATUS_URL', '/starknet/paymaster/status'),
  },
  privacy: {
    unshieldEnabled: readEnv('VITE_UNSHIELD_ENABLED', '') === 'true',
    enabled: readBool('VITE_PRIVACY_BUYIN_ENABLED'),
    poolAddress: readEnv('VITE_STRK20_POOL_ADDRESS', ''),
    anonymizerAddress: readEnv('VITE_POKER_VAULT_ANONYMIZER_ADDRESS', ''),
    provingUrl: readEnv('VITE_PRIVACY_PROVING_URL', ''),
    discoveryUrl: readEnv('VITE_PRIVACY_DISCOVERY_URL', ''),
  },
};
