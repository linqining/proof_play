// Starknet game actions for the zgame frontend.
//
// In the Starknet world the
// client only needs to talk to two contracts for chip operations:
//   1. STRK20 (canonical Sepolia STRK) — approve the vault to pull STRK
//   2. PokerVault — deposit (pulls STRK via transferFrom, credits chips 1:1)
//                   and withdraw (sends STRK back to the player)
//
// Per-hand poker actions (fold/check/call/raise) stay off-chain through the
// existing zgame/texas game server. The on-chain surface is exclusively the
// chip economy.
//
// Plan C: 写操作统一经 submitCalls() 提交 —— paymaster 中继优先（链上发送者
// 与用户地址解耦），失败自动回退 session key 直签。

import { Account, Contract, RpcProvider, BlockTag, type Abi, cairo, uint256, type AccountInterface, type Call } from 'starknet';
import { STRK20_ABI, POKER_VAULT_ABI } from './abis';
import { starknetConfig, WEI_PER_CHIP } from './config';
import { POKER_VAULT_ANONYMIZER_ABI } from './abis';
import { getProvider } from './contracts';
import { submitCalls } from './paymaster';
import { ensureTxSessionPkHex, txPkFeltHex, TX_SESSION_TTL_SECS } from './txSession';
import { buyInPrivately, isPrivateBuyInConfigured } from './privacyBuyIn';
import { logger } from '../helpers/logger';

export interface TxResult {
  /** Starknet transaction hash (hex 0x... string). */
  hash: string;
  success: boolean;
  error?: string;
}

/** 原生 STRK 写入面（买入 approve 用）。 */
function getStrk20Write(account: AccountInterface): Contract {
  return new Contract({
    abi: STRK20_ABI as Abi,
    address: CANONICAL_STRK_ADDRESS,
    providerOrAccount: account,
  });
}

function getPokerVaultWrite(account: AccountInterface): Contract {
  if (!starknetConfig.pokerVaultAddress) {
    throw new Error(
      'PokerVault address is not configured. Set VITE_POKER_VAULT_ADDRESS.',
    );
  }
  return new Contract({
    abi: POKER_VAULT_ABI as Abi,
    address: starknetConfig.pokerVaultAddress,
    providerOrAccount: account,
  });
}

/** 原生 STRK 余额（pSTRK 已下线，所有显示/买入/领取均锚定 STRK）。 */
export async function getStrkBalance(address: string): Promise<bigint> {
  try {
    const contract = new Contract({
      abi: STRK20_ABI as Abi,
      address: CANONICAL_STRK_ADDRESS,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.balance_of(address);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getStrkBalance failed:', err);
    return 0n;
  }
}

export async function getChipBalance(address: string): Promise<bigint> {
  if (!starknetConfig.pokerVaultAddress) return 0n;
  try {
    const contract = new Contract({
      abi: POKER_VAULT_ABI as Abi,
      address: starknetConfig.pokerVaultAddress,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.chip_balance(address);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getChipBalance failed:', err);
    return 0n;
  }
}

export async function getStrkAllowance(owner: string): Promise<bigint> {
  if (!starknetConfig.pokerVaultAddress) return 0n;
  try {
    const contract = new Contract({
      abi: STRK20_ABI as Abi,
      address: CANONICAL_STRK_ADDRESS,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.allowance(owner, starknetConfig.pokerVaultAddress);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getStrkAllowance failed:', err);
    return 0n;
  }
}

export async function approveStrkForVault(
  account: AccountInterface,
  amountWei: bigint,
): Promise<TxResult> {
  const owner = account.address;
  const existing = await getStrkAllowance(owner);
  if (existing >= amountWei) {
    logger.log('[starknet] existing STRK allowance covers amount, skipping approve');
    return { hash: '', success: true };
  }
  try {
    const strk = getStrk20Write(account);
    const call = strk.populate('approve', [
      starknetConfig.pokerVaultAddress,
      cairo.uint256(amountWei),
    ]);
    return await submitCalls(account, [call]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] approve failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}

export function chipsToWei(chips: number): bigint {
  return BigInt(chips) * WEI_PER_CHIP;
}

/**
 * 统一买入入口（Plan B 优先，公开路径回退）：
 * 1. 私密买入（VITE_PRIVACY_BUYIN_ENABLED 且配置就绪）：STRK20 隐私池私密
 *    交易内由 PokerVaultAnonymizer.deposit_for 给玩家记账 —— 链上看不到付款人；
 *    失败/不可用时自动回退。
 * 2. 公开路径：approve（如需）+ deposit 经 paymaster 中继或 session 直签。
 *
 * 返回的 hash 私密买入时是私密交易哈希（或空 —— 服务端以 chip_balance 为权威）。
 */
export async function submitBuyIn(
  account: AccountInterface,
  chipAmount: number,
): Promise<TxResult> {
  if (isPrivateBuyInConfigured()) {
    const priv = await buyInPrivately(account, chipsToWei(chipAmount));
    if (priv.success) {
      return { hash: priv.hash, success: true };
    }
    logger.warn('[starknet] private buy-in failed; falling back to public path:', priv.error);
  }
  return depositForBuyIn(account, chipAmount);
}

export async function depositForBuyIn(
  account: AccountInterface,
  chipAmount: number,
): Promise<TxResult> {
  const wei = chipsToWei(chipAmount);
  try {
    // approve（如需）+ 会话钥登记 + deposit 合并为一次提交：中继路径只占用
    // 一次 paymaster 通道；直签路径 session policy 对三个 entrypoint 均静默
    // 放行。
    // P1-2 会话委托：set_session_tx_pk 与 deposit 同笔登记会话交易公钥。
    // 链上登记用 x-only felt（compress 的 0x80 奇偶标志位会越出 felt252）；
    // 完整 flagged 形式走 sit_down 的 sessionTxPk 声明，服务端按 x-only
    // 掩码对拍。latest-wins 幂等；caller = 玩家钱包。
    const calls: Call[] = [];
    const txPkHex = await ensureTxSessionPkHex();
    const feltPkHex = txPkHex ? txPkFeltHex(txPkHex) : null;
    if (feltPkHex) {
      const expiresAt = Math.floor(Date.now() / 1000) + TX_SESSION_TTL_SECS;
      calls.push(
        getPokerVaultWrite(account).populate('set_session_tx_pk', [
          BigInt(`0x${feltPkHex}`),
          expiresAt,
        ]),
      );
    } else {
      logger.warn('[starknet] tx session unavailable — skipping session tx pk registration');
    }
    const existing = await getStrkAllowance(account.address);
    if (existing < wei) {
      calls.push(
        getStrk20Write(account).populate('approve', [
          starknetConfig.pokerVaultAddress,
          cairo.uint256(wei),
        ]),
      );
    }
    calls.push(getPokerVaultWrite(account).populate('deposit', [cairo.uint256(wei)]));
    return await submitCalls(account, calls);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] build deposit calls failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}

export async function withdrawFromVault(
  account: AccountInterface,
  chipAmount: number,
): Promise<TxResult> {
  const wei = chipsToWei(chipAmount);
  try {
    // Plan D P2.2 (unshield)：私密出金开启时，筹码烧毁经 anonymizer 的
    // privacy_withdraw 完成（池内 STRK 守恒，出金 note 由池私密派发，
    // 玩家筹码账户与出金地址的关联被池切断）。请求经 POST 提交到
    // proving/pool 后端做私密交易组装——这里只发起出金意图。
    if (isUnshieldEnabled()) {
      return await withdrawViaPrivacyPool(account, wei);
    }
    const vault = getPokerVaultWrite(account);
    const call = vault.populate('withdraw', [cairo.uint256(wei)]);
    return await submitCalls(account, [call]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] vault.withdraw failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}

/** VITE_UNSHIELD_ENABLED：私密出金开关（合约三件套部署齐备后开启）。 */
function isUnshieldEnabled(): boolean {
  return starknetConfig.privacy.unshieldEnabled;
}

/**
 * 私密出金意图提交：调 anonymizer 的 privacy_withdraw 需要在池的私密
 * 交易（InvokeExternal）内执行——与买入的 privacy_invoke 同机制，由
 * STRK20 钱包/SDK 的私密交易组装器发起。此处通过 STRK20 钱包 API
 * （privacyBuyIn 的同源通道）构建调用；未配置或钱包不支持时回退
 * 公开 withdraw，调用方提示用户隐私降级。
 */
async function withdrawViaPrivacyPool(
  account: AccountInterface,
  wei: bigint,
): Promise<TxResult> {
  const anonymizerAddress = starknetConfig.privacy.anonymizerAddress;
  if (!anonymizerAddress) {
    logger.warn('[starknet] unshield enabled but anonymizer address missing — public withdraw');
    const vault = getPokerVaultWrite(account);
    const call = vault.populate('withdraw', [cairo.uint256(wei)]);
    return await submitCalls(account, [call]);
  }
  try {
    const anonymizer = new Contract({
      abi: POKER_VAULT_ANONYMIZER_ABI as Abi,
      address: anonymizerAddress,
      providerOrAccount: account,
    });
    const noteId = Date.now(); // 出金 note 的客户端盐（池侧再混排）
    const call = anonymizer.populate('privacy_withdraw', [
      account.address,
      cairo.uint256(wei),
      noteId,
    ]);
    return await submitCalls(account, [call]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] privacy_withdraw failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}
/** 规范原生 STRK 地址（mainnet/Sepolia/devnet 一致）。pSTRK/swap 已下线，
 * 买入/余额/隐私池资产全部锚定原生 STRK。 */
export const CANONICAL_STRK_ADDRESS =
  '0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

export async function getNativeStrkBalance(address: string): Promise<bigint> {
  try {
    const contract = new Contract({
      abi: STRK20_ABI as Abi,
      address: CANONICAL_STRK_ADDRESS,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.balance_of(address);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getNativeStrkBalance failed:', err);
    return 0n;
  }
}

/** 查询 pSTRK 余额（PokerToken，同 getStrkBalance，语义别名）。 */
export async function getPstrkBalance(address: string): Promise<bigint> {
  return getStrkBalance(address);
}
