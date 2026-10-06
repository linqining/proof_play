// Plan B：私密买入通道（STRK20 privacy pool + PokerVaultAnonymizer）。
//
// 资金流程：用户的 STRK 先 shield 进 STRK20 隐私池（钱包一键或 SDK deposit），
// 买入时在私密交易内由 PokerVaultAnonymizer.privacy_invoke 调
// PokerVault.deposit_for(player, amount) 给玩家记账。链上观察者看不到付款人
//（私密 note + ZK 证明）；只能看到 anonymizer 给玩家记账这一公开动作。
// 结合方案 C（paymaster 中继提交），提交者也不是用户地址 —— 提交环节无法
// 按用户身份定向审查（B 隐藏资金来源，C 隐藏提交者）。
//
// 两个后端，运行时探测、任一失败自动回退公开路径（submitCalls / 直签）：
// - wallet-api：STRK20-capable 钱包（Ready X / Xverse 等）的
//   `account.strk20InvokeTransaction(actions)`。要求用户已 shield（钱包 UI
//   一键入池），游戏侧只发 anonymizer invoke 动作。open note 占位符
//   `${openNoteIds[0]}` 由钱包在执行时填充找零 note。
// - sdk：`@starkware-libs/starknet-privacy-sdk`（发布于 GitHub Packages，
//   Node ≥ 24，RC 阶段）。动态加载 —— 未安装时探测失败即回退。register /
//   deposit 按官方 strk20-by-example 示例实现；deposit+invoke 组合依赖 SDK
//   builder 上的 invoke 方法，运行时探测（见 tryComposeInvoke），缺失即回退。
//
// 服务端校验不变：SIT_DOWN_V2 带 depositTxHash（私密买入为空），
// chips.verify_deposit 以 vault.chip_balance(player) 为权威。

import { type AccountInterface } from 'starknet';
import { logger } from '../helpers/logger';
import { starknetConfig, toWalletFeltHex } from './config';
import { getProvider } from './contracts';

const SDK_MODULE = '@starkware-libs/starknet-privacy-sdk';
const OPEN_NOTE_PLACEHOLDER = '${openNoteIds[0]}';
/** 证明锚定 block（note 成熟需要 10 个区块）。 */
const PROVING_BLOCK_LAG = 10;

export interface PrivateBuyInResult {
  /** 实际尝试了私密路径（配置就绪 + 后端可用）。 */
  attempted: boolean;
  /** 成功使用的后端。 */
  backend?: 'wallet-api' | 'sdk';
  /** 私密交易哈希（可能为空 —— 由 paymaster 广播时仍能拿到）。 */
  hash: string;
  success: boolean;
  error?: string;
}

/**
 * 配置层面是否启用私密买入（不含 SDK/钱包能力探测）。
 * wallet-api 后端只需池 + anonymizer 地址（证明由钱包内部完成）；
 * proving/discovery URL 仅 SDK 后端需要（需自建服务，主网无公开端点），
 * 缺省时 buyInPrivately 跳过 SDK 路径，不影响 wallet-api。
 */
export function isPrivateBuyInConfigured(): boolean {
  const p = starknetConfig.privacy;
  return p.enabled && !!p.poolAddress && !!p.anonymizerAddress;
}

// ------------------------------------------------------------
// Viewing key（每个用户本地生成并持有，不进构建产物/环境变量）
// ------------------------------------------------------------

const VK_STORAGE_PREFIX = 'zp_viewing_key_';

async function getViewingKey(address: string): Promise<string> {
  const key = VK_STORAGE_PREFIX + address.toLowerCase();
  let vk = localStorage.getItem(key);
  if (!vk) {
    const bytes = new Uint8Array(31);
    crypto.getRandomValues(bytes);
    bytes[0] &= 0x7f; // 保持 < 2^248（felt 安全）
    vk = '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem(key, vk);
    logger.log('[starknet-privacy] generated new viewing key for', address);
  }
  return vk;
}

// ------------------------------------------------------------
// SDK 动态加载（非字面量 specifier → vite 不做预打包/解析）
// ------------------------------------------------------------

/** 官方 SDK 的最小结构面（strk20-by-example 文档化 API 的运行时探测视图）。 */
interface SDKCallAndProof {
  call: unknown;
  proof: { proofFacts?: string[]; data?: unknown };
}
interface SDKTokenOps {
  deposit(options: { amount: bigint }): unknown;
  inputs(...notes: unknown[]): SDKTokenOps;
  invoke?: (options: { contract: string; calldata: unknown[] }) => unknown;
}
interface SDKBuilder {
  register(): SDKBuilder;
  surplusTo(address: string): SDKBuilder;
  with(token: string, fn: (t: SDKTokenOps) => unknown): SDKBuilder;
  execute(options: { provingBlockId: number }): Promise<SDKCallAndProof>;
}
interface SDKModule {
  createPrivateTransfers(options: Record<string, unknown>): {
    build(options?: { autoSetup?: boolean }): SDKBuilder;
  };
}

let sdkProbe: Promise<SDKModule | null> | null = null;

function loadSdk(): Promise<SDKModule | null> {
  if (!sdkProbe) {
    sdkProbe = (async () => {
      try {
        const spec = SDK_MODULE;
        const mod = (await import(/* @vite-ignore */ spec)) as SDKModule;
        if (typeof mod?.createPrivateTransfers !== 'function') {
          throw new Error('unexpected SDK module shape');
        }
        logger.log('[starknet-privacy] SDK loaded');
        return mod;
      } catch (err) {
        logger.log('[starknet-privacy] SDK not available:', (err as Error).message);
        return null;
      }
    })();
  }
  return sdkProbe;
}

// ------------------------------------------------------------
// 后端实现
// ------------------------------------------------------------

/** u256 → [low, high] 两个 0x 十六进制 felt（钱包 payload schema 只认
 * 规范化 0x hex：十进制串、前导零、'0x' 空 hex 都会被
 * INVALID_REQUEST_PAYLOAD 拒绝；SDK CallData 两者皆收）。 */
function splitU256(wei: bigint): [string, string] {
  const mask = (1n << 128n) - 1n;
  return [toWalletFeltHex(wei & mask), toWalletFeltHex(wei >> 128n)];
}

/** helper 的 privacy_invoke operation：0 = 买入（STRK → 筹码）。 */
const OP_BUY_IN = '0x0';

/** 读 vault.chip_balance(player)（u256 wei）；RPC 抖动返回 -1n 由调用方重试。 */
async function readChipBalance(player: string): Promise<bigint> {
  const vault = starknetConfig.pokerVaultAddress;
  if (!vault) return -1n;
  try {
    const res = await getProvider().callContract({
      contractAddress: vault,
      entrypoint: 'chip_balance',
      calldata: [player],
    });
    const arr = Array.isArray(res) ? res : ((res as { result?: string[] }).result ?? []);
    return BigInt(arr[0] ?? 0) + (BigInt(arr[1] ?? 0) << 128n);
  } catch {
    return -1n;
  }
}

/**
 * 链上对账：轮询 vault.chip_balance(player) 直到余额 ≥ before + deltaWei。
 * 买入是否入账以链上为准、以玩家地址记账——后端确认失败（回执拉取失败等）
 * 只影响上桌记账，不影响资金安全；玩家随时可 vault.withdraw 自助取回。
 */
async function waitForChipsOnChain(
  player: string,
  deltaWei: bigint,
  before: bigint,
  timeoutMs = 120_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = before;
  while (Date.now() < deadline) {
    const bal = await readChipBalance(player);
    if (bal >= 0n) {
      last = bal;
      if (bal >= before + deltaWei) {
        logger.log('[starknet-privacy] chips confirmed on-chain:', bal.toString());
        return;
      }
    }
    await new Promise((r) => setTimeout(r, 6000));
  }
  logger.warn(
    '[starknet-privacy] chip_balance poll timed out (last:',
    last.toString(),
    ') — funds remain on-chain under the player; backend reconcile or vault.withdraw will recover.',
  );
}

/**
 * Wallet-API 后端：STRK20-capable 钱包执行 anonymizer invoke 私密动作。
 * 要求用户已在钱包内 shield（入池持有私密 note）。
 */
async function walletApiBackend(account: AccountInterface, wei: bigint): Promise<PrivateBuyInResult> {
  const acct = account as AccountInterface & {
    strk20InvokeTransaction?: (actions: unknown[]) => Promise<{ transaction_hash: string }>;
  };
  if (typeof acct.strk20InvokeTransaction !== 'function') {
    throw new Error('wallet does not expose strk20InvokeTransaction');
  }

  const before = await readChipBalance(account.address);
  const [low, high] = splitU256(wei);
  const actions = [
    {
      type: 'invoke',
      contract: starknetConfig.privacy.anonymizerAddress,
      // privacy_invoke(operation=0 买入, player, amount:u256, change_note_id)
      calldata: [OP_BUY_IN, toWalletFeltHex(account.address), low, high, OPEN_NOTE_PLACEHOLDER],
    },
  ];
  const res = await acct.strk20InvokeTransaction(actions);
  await getProvider().waitForTransaction(res.transaction_hash);
  // 链上对账：买入的筹码以 vault.chip_balance 为权威，不依赖后端确认
  //（后端拉回执失败 ≠ 资金丢失；此处直接向链上要结论）。
  if (before >= 0n) {
    await waitForChipsOnChain(account.address, wei, before);
  }
  return { attempted: true, backend: 'wallet-api', hash: res.transaction_hash, success: true };
}

/** SDK 提交尾部：证明事实非空时附加，tip: 0n 为 v3 交易强制要求。 */
async function submitSdkCallAndProof(
  account: AccountInterface,
  callAndProof: SDKCallAndProof,
): Promise<string> {
  const proofDetails = callAndProof.proof.proofFacts?.length
    ? { proofFacts: callAndProof.proof.proofFacts, proof: callAndProof.proof.data }
    : {};
  const tx = await account.execute(callAndProof.call as never, {
    tip: 0n,
    ...proofDetails,
  } as never);
  await getProvider().waitForTransaction(tx.transaction_hash);
  return tx.transaction_hash;
}

/**
 * SDK 后端：register（一次性）→ approve → deposit + invoke 私密组合。
 * invoke 组合方法缺失时抛错（调用方回退公开路径）。
 */
async function sdkBackend(account: AccountInterface, wei: bigint): Promise<PrivateBuyInResult> {
  const sdk = await loadSdk();
  if (!sdk) throw new Error('privacy SDK not installed');
  const cfg = starknetConfig.privacy;
  const provider = getProvider();

  const transfers = sdk.createPrivateTransfers({
    account,
    viewingKeyProvider: {
      getViewingKey: async () => BigInt(await getViewingKey(account.address)),
    },
    provingProvider: { url: cfg.provingUrl, chainId: starknetConfig.chainId },
    discoveryProvider: { url: cfg.discoveryUrl },
    poolContractAddress: cfg.poolAddress,
  });

  const provingBlockId = async () =>
    Math.max(0, (await provider.getBlockNumber()) - PROVING_BLOCK_LAG);

  // 一次性注册（加密 viewing key 上链）。
  const registeredFlag = `zp_registered_${account.address.toLowerCase()}`;
  if (!localStorage.getItem(registeredFlag)) {
    const reg = await transfers.build().register().execute({ provingBlockId: await provingBlockId() });
    await submitSdkCallAndProof(account, reg);
    localStorage.setItem(registeredFlag, '1');
    logger.log('[starknet-privacy] registered viewing key on-chain');
  }

  // apply_actions 有重入保护：approve 必须先单独落地，再发私密交易。
  const approveTx = await account.execute(
    {
      contractAddress: starknetConfig.strk20Address,
      entrypoint: 'approve',
      calldata: [cfg.poolAddress, wei.toString(), '0'],
    },
    { tip: 0n } as never,
  );
  await provider.waitForTransaction(approveTx.transaction_hash);

  // deposit + invoke 组合：invoke builder 方法运行时探测。
  // anonymizer calldata = privacy_invoke(player, amount: u256, change_note_id)。
  const [low, high] = splitU256(wei);
  const build = transfers.build({ autoSetup: true });
  const executable = build
    .surplusTo(account.address)
    .with(starknetConfig.strk20Address, (t) => {
      const composed = tryComposeInvoke(t, account.address, low, high);
      if (!composed) {
        throw new Error(
          'SDK builder has no invoke(); cannot compose private buy-in (SDK_SEAM)',
        );
      }
      return composed;
    });
  const callAndProof = await executable.execute({ provingBlockId: await provingBlockId() });
  const hash = await submitSdkCallAndProof(account, callAndProof);
  return { attempted: true, backend: 'sdk', hash, success: true };
}

/** 探测 SDK token builder 的 invoke 组合入口（直接方法或 deposit 链式）。 */
function tryComposeInvoke(
  t: SDKTokenOps,
  player: string,
  low: string,
  high: string,
): unknown {
  const invokeOptions = {
    contract: starknetConfig.privacy.anonymizerAddress,
    // privacy_invoke(operation=0 买入, player, amount:u256, change_note_id)
    calldata: [OP_BUY_IN, player, low, high, OPEN_NOTE_PLACEHOLDER],
  };
  if (typeof t.invoke === 'function') {
    return t.invoke(invokeOptions);
  }
  return undefined;
}

// ------------------------------------------------------------
// 入口
// ------------------------------------------------------------

/**
 * 执行私密买入：wallet-api 后端优先（无 SDK 依赖），SDK 后端其次。
 * 任一后端不可用/失败返回 attempted=true + success=false，由调用方回退
 * 公开路径（submitCalls —— 方案 C）。
 */
export async function buyInPrivately(
  account: AccountInterface,
  wei: bigint,
): Promise<PrivateBuyInResult> {
  const backends: Array<[PrivateBuyInResult['backend'], () => Promise<PrivateBuyInResult>]> = [
    ['wallet-api', () => walletApiBackend(account, wei)],
  ];
  // SDK 后端需要自建 proving/discovery 服务（主网无公开端点）；未配置即跳过。
  if (starknetConfig.privacy.provingUrl && starknetConfig.privacy.discoveryUrl) {
    backends.push(['sdk', () => sdkBackend(account, wei)]);
  }
  let lastError: unknown;
  for (const [name, run] of backends) {
    try {
      const result = await run();
      logger.log(`[starknet-privacy] buy-in via ${name}:`, result.hash);
      return result;
    } catch (err) {
      lastError = err;
      logger.warn(`[starknet-privacy] ${name} backend failed:`, err);
    }
  }
  return {
    attempted: true,
    hash: '',
    success: false,
    error: lastError instanceof Error ? lastError.message : String(lastError),
  };
}
