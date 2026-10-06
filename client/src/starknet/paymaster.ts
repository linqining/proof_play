// Plan C：paymaster 提交通道（中继优先，直签回退）。
//
// 目标是把"交易提交者"与"用户"解耦：客户端持 starknet.js PaymasterRpc，
// 指向 game server 的 /api/starknet/paymaster 中继（服务端注入 x-api-key 后
// 透传给上游 paymaster，如 AVNU）。流程：
//   1. paymaster_buildTransaction(calls) → OutsideExecution typed data
//   2. 用户账户对 typed data 签名（签名留在客户端）
//   3. paymaster_executeTransaction → 上游以自己的账户合约广播交易，
//      链上交易发送者不是用户地址 → 无法按用户身份定向审查
//
// 任一环节失败（服务端未配置中继 / 上游不可用 / 钱包拒绝签名）自动回退
// account.execute —— Cartridge session policy 内的 approve/deposit/withdraw
// 仍由 session key 静默放行，功能不中断。
//
// 注意：session 覆盖的 entrypoint 直签是静默的；paymaster 路径的 typed data
// 签名可能触发一次钱包确认（OutsideExecution 不在 contract policy 模型内）。

import {
  PaymasterRpc,
  type AccountInterface,
  type Call,
  type ExecutionParameters,
  type ExecutableUserTransaction,
  type UserTransaction,
} from 'starknet';
import { httpClient } from '../helpers/httpClient';
import { logger } from '../helpers/logger';
import { starknetConfig } from './config';
import { getProvider } from './contracts';
import type { TxResult } from './starknetGameActions';

let cachedConfigured: Promise<boolean> | null = null;

/** 探测服务端中继是否已配置（结果缓存；探测失败按未配置处理）。 */
export function isRelayConfigured(): Promise<boolean> {
  if (starknetConfig.paymaster.disabled) {
    return Promise.resolve(false);
  }
  if (!cachedConfigured) {
    cachedConfigured = httpClient
      .get<{ configured: boolean }>(starknetConfig.paymaster.statusUrl)
      .then((res) => res.data?.configured === true)
      .catch((err) => {
        logger.warn('[starknet-paymaster] status probe failed; using direct path', err);
        return false;
      });
  }
  return cachedConfigured;
}

let paymasterRpc: PaymasterRpc | null = null;

function getPaymaster(): PaymasterRpc {
  if (!paymasterRpc) {
    paymasterRpc = new PaymasterRpc({
      nodeUrl: starknetConfig.paymaster.relayUrl,
    });
  }
  return paymasterRpc;
}

function executionParameters(): ExecutionParameters {
  const feeMode =
    starknetConfig.paymaster.feeMode === 'default'
      ? { mode: 'default' as const, gasToken: starknetConfig.paymaster.gasToken }
      : { mode: 'sponsored' as const };
  return { version: '0x1', feeMode };
}

/** 中继路径：build → 用户签名 → 上游广播，返回链上交易哈希。 */
async function executeViaPaymaster(account: AccountInterface, calls: Call[]): Promise<string> {
  const pm = getPaymaster();
  if (!(await pm.isAvailable())) {
    throw new Error('paymaster relay not available');
  }

  const transaction: UserTransaction = {
    type: 'invoke',
    invoke: { userAddress: account.address, calls },
  };
  const parameters = executionParameters();
  const prepared = await pm.buildTransaction(transaction, parameters);
  if (prepared.type !== 'invoke') {
    throw new Error(`unexpected prepared transaction type: ${prepared.type}`);
  }

  // OutsideExecution typed data 与 SNIP-12 TypedData 结构兼容；类型上做强转。
  type SignMessageInput = Parameters<AccountInterface['signMessage']>[0];
  const signature = await account.signMessage(prepared.typed_data as unknown as SignMessageInput);
  const sigArray = (Array.isArray(signature) ? signature : [signature.r, signature.s]).map(String);

  const executable: ExecutableUserTransaction = {
    type: 'invoke',
    invoke: { userAddress: account.address, typedData: prepared.typed_data, signature: sigArray },
  };
  const res = (await pm.executeTransaction(executable, parameters)) as {
    transaction_hash?: string;
    tracking_id?: string;
  };
  if (!res.transaction_hash) {
    throw new Error('paymaster executeTransaction returned no transaction_hash');
  }
  return res.transaction_hash;
}

export type SubmitPath = 'paymaster' | 'direct';

export interface SubmitResult extends TxResult {
  /** 实际使用的提交通道（UI 可展示 / 排障）。 */
  path: SubmitPath;
}

/** 缓存"已确认未部署"的账户地址，避免每次提交都多打一发 RPC。 */
const knownUndeployed = new Set<string>();

/**
 * 钱包智能账户在当前链未部署时，直发 invoke 必然失败且钱包插件不会代为
 * 部署：插件按 chain id 缓存部署状态，devnet 与 Sepolia 同为 SN_SEPOLIA，
 * 在 Sepolia 部署过的账户会被误判为已部署（本地联调高频踩坑）。这里显式
 * 探测并返回可操作的错误，提示用户重连钱包触发插件自身的部署流程。
 */
async function assertWalletDeployed(account: AccountInterface): Promise<string | null> {
  const addr = account.address.toLowerCase();
  if (knownUndeployed.has(addr)) {
    return '钱包账户在当前网络未部署（wallet account not deployed）：请断开并重新连接钱包（触发钱包插件的部署流程）；本地联调还需确认插件网络已指向本地 devnet。';
  }
  try {
    await getProvider().getClassHashAt(addr);
    return null;
  } catch {
    knownUndeployed.add(addr);
    logger.warn('[starknet-paymaster] wallet account undeployed on current chain:', addr);
    return '钱包账户在当前网络未部署（wallet account not deployed）：请断开并重新连接钱包（触发钱包插件的部署流程）；本地联调还需确认插件网络已指向本地 devnet。';
  }
}

/**
 * 统一交易提交入口：paymaster 中继优先，失败/未配置回退 session 直签。
 * 两条路径都等待回执（经多 RPC failover provider）后返回。
 */
export async function submitCalls(
  account: AccountInterface,
  calls: Call[],
): Promise<SubmitResult> {
  if (calls.length === 0) {
    return { hash: '', success: true, path: 'direct' };
  }

  const notDeployed = await assertWalletDeployed(account);
  if (notDeployed) {
    return { hash: '', success: false, error: notDeployed, path: 'direct' };
  }

  if (await isRelayConfigured()) {
    try {
      const hash = await executeViaPaymaster(account, calls);
      await getProvider().waitForTransaction(hash);
      logger.log('[starknet-paymaster] submitted via paymaster relay:', hash);
      return { hash, success: true, path: 'paymaster' };
    } catch (err) {
      logger.warn('[starknet-paymaster] relay path failed; falling back to direct:', err);
    }
  }

  try {
    const tx = await account.execute(calls);
    await getProvider().waitForTransaction(tx.transaction_hash);
    return { hash: tx.transaction_hash, success: true, path: 'direct' };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet-paymaster] direct submission failed:', msg);
    return { hash: '', success: false, error: msg, path: 'direct' };
  }
}
