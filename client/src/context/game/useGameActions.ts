import { useContext, useEffect, useRef, useState, type MutableRefObject } from 'react';
import type { NavigateFunction } from 'react-router-dom';
import type { Socket } from 'socket.io-client';
import { extractC1, ownHoleC1Set } from './ownHoleCards';
import { signTableAction, sigToPayloadFields } from './actionSigning';
import type { WasmClientPlayer } from '@linqining/client-wasm';
import {
  CALL,
  CHECK,
  FOLD,
  JOIN_TABLE,
  LEAVE_TABLE,
  RAISE,
  REBUY,
  SIT_DOWN_V2,
  STAND_UP,
  SITTING_OUT,
  SITTING_IN,
  RECONSTRUCT_INITIATE,
  TABLE_UPDATED,
} from '../../pokergame/actions';
import { getToken } from '../../helpers/getToken';
import httpClient from '../../helpers/httpClient';
import type { Table, Seat } from '../../types/game';
import { RoundState } from '../../types/game';
import { TableUpdatedPayload, wrapCryptoOp } from './gameInternal';
import authContext from '../../context/auth/authContext';
import { logger } from '../../helpers/logger';
import { STAND_UP_TIMEOUT_MS } from '../../clientConfig';
import { useAccount } from '@starknet-react/core';
import { submitBuyIn } from '../../starknet/starknetGameActions';
import { ensureTxSessionPkHex } from '../../starknet/txSession';
import { activeAccount } from '../../starknet/devAccount';
import { isZChainSession, zchainSignBuyIn } from '../../starknet/zchainWallet';
import { isMonadSession, monadBuyInDeposit } from '../../starknet/monadWallet';
import { useGlobalContext } from '../global/globalContext';

export interface UseGameActionsParams {
  socket: Socket | null;
  navigate: NavigateFunction;
  playerKeys: WasmClientPlayer | null;
  pkHex: string | null;
  getPlayerKeys: () => WasmClientPlayer | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  /** 当前 table 状态（来自 React state，用于在 useEffect 中响应 roundState 变化） */
  currentTable: Table | null;
  seatId: number | null;
  isPlayerSeated: boolean;
  /** 后端因手牌进行中而推迟离桌时（LEAVE_DEFERRED 事件）置为 true */
  leaveDeferred: boolean;
  setLeaveDeferred: (value: boolean) => void;
  authMethod: string | null;
}

export interface UseGameActionsReturn {
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
  rebuy: (tableId: string, seatId: number, amount: number) => void;
  standUp: () => Promise<void>;
  fold: () => void;
  check: () => void;
  call: () => void;
  raise: (amount: number) => void;
  sittingOut: () => void;
  sittingIn: () => void;
  expelInitiate: (tableId: string, targetPlayerPk: string) => void;
  /** 当玩家在手牌进行中且未 fold 时点击离开，置为 true 以触发确认弹窗（Task 7 渲染弹窗） */
  showFoldLeaveConfirm: boolean;
  /** 用户确认 fold 并离开：调用 fold() 后进入 deferred leave 流程 */
  confirmFoldLeave: (shouldNavigate?: boolean, pkHex?: string) => void;
  /** 用户取消 fold 并离开 */
  cancelFoldLeave: () => void;
  /** 用户在 deferred banner 上取消离开：中断进行中的 performDeferredLeave */
  cancelDeferredLeave: () => void;
}

export const useGameActions = (params: UseGameActionsParams): UseGameActionsReturn => {
  const {
    socket,
    navigate,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    currentTable,
    seatId,
    isPlayerSeated,
    leaveDeferred,
    setLeaveDeferred,
  } = params;

  const { walletAddress } = useContext(authContext)!;
  // 买入差额判断用（monad 会话）：异步闭包读最新值，state 快照会过期。
  const { chipsAmount } = useGlobalContext();
  const chipsAmountRef = useRef(chipsAmount);
  useEffect(() => {
    chipsAmountRef.current = chipsAmount;
  }, [chipsAmount]);
  const connected = useAccount();
  // dev 直签账户（VITE_DEV_ACCOUNT_*，testnet 联调）优先于连接的钱包
  const account = activeAccount(connected.account);
  // useAccount 的值在闭包里是渲染时快照——sitDown 异步等待账户时必须
  // 读最新值（钱包扩展重连慢/刷新后立刻点入座时快照还是 null，
  // 2026-09-08 线上 "[SitDown] No Starknet account available"）。
  const accountRef = useRef(account);
  accountRef.current = account;

  /**
   * 等待 starknet-react 完成钱包账户水合（刷新/重连后扩展回连有几秒
   * 延迟）。返回 null = 超时，调用方给出可操作提示。
   */
  const waitForAccount = async (timeoutMs = 6000): Promise<typeof account | null> => {
    if (accountRef.current) return accountRef.current;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 300));
      if (accountRef.current) return accountRef.current;
    }
    return null;
  };

  /**
   * 当玩家在手牌进行中且未 fold 时点击离开，置为 true 以触发确认弹窗。
   * Task 7 负责渲染弹窗；本 hook 只暴露状态和 confirm/cancel 处理函数。
   */
  const [showFoldLeaveConfirm, setShowFoldLeaveConfirm] = useState(false);
  // 保存触发确认弹窗时的 leaveTable 调用参数，供 confirmFoldLeave 使用
  const pendingLeaveParamsRef = useRef<{ shouldNavigate: boolean; pkHex?: string }>({
    shouldNavigate: true,
  });
  // 防止 performDeferredLeave 并发执行
  const deferredLeaveInFlightRef = useRef(false);
  // 捕获进入 deferred leave 流程时的原始 tableId / pkHex / 取消标志。
  // 必须使用 ref 而非 currentTableRef：用户可能在 Waiting 到来前导航离开并加入新表，
  // 此时 currentTableRef.current 指向新表，会对错误的表执行 standUp + LEAVE_TABLE。
  const deferredLeaveCtxRef = useRef<{
    tableId: number | string | null;
    pkHex: string;
    cancelled: boolean;
  }>({ tableId: null, pkHex: '', cancelled: false });

  // 进入 deferred leave 流程：捕获原始 tableId/pkHex 并设置 leaveDeferred
  const enterDeferredLeave = (
    tableId: number | string | null,
    pkHexToUse: string,
    shouldNavigate: boolean,
  ) => {
    deferredLeaveCtxRef.current = {
      tableId,
      pkHex: pkHexToUse,
      cancelled: false,
    };
    setLeaveDeferred(true);
    if (shouldNavigate) navigate('/');
  };

  // 用户在 deferred banner 上点击"取消离开"：置位 cancelled 以中断进行中的 performDeferredLeave
  const cancelDeferredLeave = () => {
    deferredLeaveCtxRef.current.cancelled = true;
    setLeaveDeferred(false);
  };

  const joinTable = (tableId: number, pk: string) => {
    logger.log(JOIN_TABLE, { tableId, pkHex: pk });
    socket?.emit(JOIN_TABLE, { tableId, pkHex: pk });
  };

  const leaveTable = async (shouldNavigate = true, pk?: string, fireAndForget = false) => {
    // 简化离桌：直接 emit LEAVE_TABLE——服务器 kick_player 处理手牌中离开
    // （fold + side pot 保留），不发钱包交易、不做 deck 剥层。
    // 页面卸载 fireAndForget 同理。
    const tid = currentTableRef.current?.id;
    if (tid != null) {
      socket?.emit(LEAVE_TABLE, { tableId: tid, pkHex: pk || '' });
    }
    setLeaveDeferred(false);
    if (shouldNavigate) navigate('/');
  };

  /**
   * 当 roundState 转为 Waiting 且 leaveDeferred == true 时执行真正的离桌操作。
   * 使用 deferredLeaveCtxRef 中捕获的原始 tableId/pkHex，避免用户换桌后离错表；
   * 在 await standUp() 前后检查 cancelled 标志，支持 banner 取消中断。
   */
  const performDeferredLeave = async () => {
    if (deferredLeaveInFlightRef.current) return;
    const ctx = deferredLeaveCtxRef.current;
    if (!ctx.tableId) {
      setLeaveDeferred(false);
      return;
    }
    deferredLeaveInFlightRef.current = true;
    try {
      await standUp();
      // await 期间用户可能点了 banner "取消离开"，此时不应继续 emit LEAVE_TABLE
      if (deferredLeaveCtxRef.current.cancelled) {
        return;
      }
      socket?.emit(LEAVE_TABLE, { tableId: ctx.tableId, pkHex: ctx.pkHex || '' });
      setLeaveDeferred(false);
    } catch (e) {
      logger.error('[performDeferredLeave] failed:', e);
      addMessage(`Failed to complete leave: ${(e as Error).message || e}`);
      setLeaveDeferred(false);
    } finally {
      deferredLeaveInFlightRef.current = false;
    }
  };

  /**
   * 监听 leaveDeferred + currentTable.roundState：
   * 当 leaveDeferred == true 且 roundState == Waiting 时，执行 deferred leave。
   */
  useEffect(() => {
    if (!leaveDeferred) return;
    const roundState = currentTable?.roundState;
    if (roundState === RoundState.Waiting) {
      performDeferredLeave();
    }
  }, [leaveDeferred, currentTable]); // eslint-disable-line react-hooks/exhaustive-deps

  /**
   * 用户在确认弹窗中点击"确认 fold 并离开"。
   * 调用 fold() 后进入 deferred leave 流程（与已 fold 路径相同）。
   */
  const confirmFoldLeave = (shouldNavigate = true, pkHexArg?: string) => {
    setShowFoldLeaveConfirm(false);
    const table = currentTableRef.current;
    const tableId = table?.id;
    const usePkHex = pkHexArg ?? pkHex ?? '';
    if (!tableId) {
      setLeaveDeferred(false);
      return;
    }
    // 先 fold（后端会更新 seat.folded = true）
    fold();
    // 标记 sitting_out + deferred leave
    socket?.emit(STAND_UP, { tableId, pkHex: usePkHex || null, leaveRound: null });
    enterDeferredLeave(tableId, usePkHex, shouldNavigate);
  };

  /**
   * 用户在确认弹窗中点击"取消"：仅清除弹窗状态，不执行任何离桌操作。
   */
  const cancelFoldLeave = () => {
    setShowFoldLeaveConfirm(false);
    pendingLeaveParamsRef.current = { shouldNavigate: true };
  };

  const sitDown = async (tableId: string, seatIdNum: number, amount: number) => {
    // 关桌终态前置拦截：服务端 SIT_DOWN 也会以 TABLE_CLOSED 拒绝，
    // 这里只是省一次无谓的买入流程。
    if (currentTableRef.current?.closed) {
      logger.warn('[SitDown] table is closed — rejected locally');
      addMessage('本桌已关闭，不再接受入座 / Table closed');
      return;
    }
    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      logger.error('[SitDown] No player keys available');
      addMessage('Cannot sit down: no player keys');
      return;
    }
    if (!pkHex) {
      logger.error('[SitDown] No pkHex available');
      addMessage('Cannot sit down: no public key');
      return;
    }
    if (!currentTableRef.current) {
      logger.error('[SitDown] No current table');
      addMessage('Cannot sit down: no table data');
      return;
    }
    const token = getToken();
    if (!token) {
      logger.error('[SitDown] No auth token available');
      addMessage('Cannot sit down: please connect your wallet first');
      return;
    }
    if (!walletAddress) {
      logger.error('[SitDown] No wallet connected');
      addMessage('Cannot sit down: no wallet connected');
      return;
    }
    // ----- ZChain 钱包买入：扩展弹窗签 buy_in 结构化操作（真实验名），
    //       不走 Starknet 链上 vault.deposit（结算出口为 appchain→zchain 的
    //       dev 部署，服务端对无 depositTxHash 的入座跳过链上核验）。 -----
    if (isZChainSession()) {
      const token = getToken();
      if (!token || !walletAddress || !currentTableRef.current) {
        addMessage('Cannot sit down: no wallet connected');
        return;
      }
      let buyinDigest = '';
      try {
        addMessage('Confirming buy-in in ProofPlay Wallet...');
        buyinDigest = await zchainSignBuyIn(walletAddress, Number(tableId));
      } catch (e) {
        const err = e as { code?: string; message?: string };
        logger.error('[SitDown] ZChain buy_in signing failed:', err);
        addMessage(`Sit down failed: ProofPlay Wallet ${err?.code ?? ''} ${err?.message ?? e}`);
        return;
      }
      let pkProof: unknown;
      try {
        const proofRaw = wrapCryptoOp(() => keys.generate_pk_proof(), 'generate_pk_proof') as string | object;
        pkProof = typeof proofRaw === 'string' ? JSON.parse(proofRaw) : proofRaw;
      } catch (e) {
        const err = e as Error;
        logger.error('[SitDown] pk proof generation failed:', err);
        addMessage(`Sit down failed: ${err.message || err}`);
        return;
      }
      const outcome = await new Promise<{ failed: boolean; msg: string } | null>((resolve) => {
        let settled = false;
        const onErr = (data: { msg?: string; action?: string }) => {
          if (data?.action !== 'sit_down' || settled) return;
          settled = true;
          socket?.off('error', onErr);
          resolve({ failed: true, msg: data.msg ?? 'sit down rejected' });
        };
        socket?.on('error', onErr);
        socket?.emit(SIT_DOWN_V2, {
          token,
          tableId,
          seatId: seatIdNum,
          amount,
          pkHex,
          pkProof,
          // 扩展 buy_in 签名摘要作为买入凭证：携带 deposit 凭证即跳过
          // 服务端余额预检，dev 结算模式下 verify_deposit 自动放行。
          depositTxHash: buyinDigest ? `zchain-buyin:${buyinDigest}` : undefined,
        });
        setTimeout(() => {
          if (!settled) {
            settled = true;
            socket?.off('error', onErr);
            resolve(null);
          }
        }, 6000);
      });
      if (outcome === null) {
        addMessage('Joined table (ProofPlay Wallet buy-in confirmed)');
        logger.log('[SitDown] zchain join accepted');
        return;
      }
      addMessage(`Sit down failed: ${outcome.msg}`);
      logger.error('[SitDown] zchain join rejected:', outcome.msg);
      return;
    }

    // ----- Monad 钱包买入：L1Bridge.depositNative 锁 MON（contracts/monad）。
    //       差额上链——服务端 note 余额已覆盖买入额时跳过交易直接入座；
    //       否则钱包签名补差额，回执哈希随 SIT_DOWN_V2 上送，服务端核验
    //       DepositInitiated 事件 + 存款桥铸 note。 -----
    if (isMonadSession()) {
      const token = getToken();
      if (!token || !walletAddress || !currentTableRef.current) {
        addMessage('Cannot sit down: no wallet connected');
        return;
      }
      let depositTxHash: string | undefined;
      const available = chipsAmountRef.current ?? 0;
      if (available < amount) {
        try {
          const shortfall = amount - available;
          addMessage(`Confirming MON buy-in in wallet (${shortfall} chips via L1Bridge deposit)...`);
          const receipt = await monadBuyInDeposit(shortfall);
          depositTxHash = receipt.transactionHash;
          logger.log('[SitDown] L1Bridge deposit tx:', depositTxHash);
        } catch (e) {
          const err = e as { message?: string };
          logger.error('[SitDown] Monad L1Bridge buy-in failed:', err);
          addMessage(`Sit down failed: Monad buy-in ${err?.message ?? e}`);
          return;
        }
      } else {
        logger.log('[SitDown] note balance covers buy-in — skipping on-chain deposit');
      }
      let pkProof: unknown;
      try {
        const proofRaw = wrapCryptoOp(() => keys.generate_pk_proof(), 'generate_pk_proof') as string | object;
        pkProof = typeof proofRaw === 'string' ? JSON.parse(proofRaw) : proofRaw;
      } catch (e) {
        const err = e as Error;
        logger.error('[SitDown] pk proof generation failed:', err);
        addMessage(`Sit down failed: ${err.message || err}`);
        return;
      }
      const outcome = await new Promise<{ failed: boolean; msg: string } | null>((resolve) => {
        let settled = false;
        const onErr = (data: { msg?: string; action?: string }) => {
          if (data?.action !== 'sit_down' || settled) return;
          settled = true;
          socket?.off('error', onErr);
          resolve({ failed: true, msg: data.msg ?? 'sit down rejected' });
        };
        socket?.on('error', onErr);
        socket?.emit(SIT_DOWN_V2, {
          token,
          tableId,
          seatId: seatIdNum,
          amount,
          pkHex,
          pkProof,
          // L1Bridge 回执哈希即买入凭证：服务端 monad 桌面核验回执 +
          // DepositInitiated 事件并即时铸 note（差额部分上链，见上）。
          depositTxHash,
        });
        setTimeout(() => {
          if (!settled) {
            settled = true;
            socket?.off('error', onErr);
            resolve(null);
          }
        }, 6000);
      });
      if (outcome === null) {
        addMessage('Joined table (Monad L1Bridge buy-in confirmed)');
        logger.log('[SitDown] monad join accepted');
        return;
      }
      addMessage(`Sit down failed: ${outcome.msg}`);
      logger.error('[SitDown] monad join rejected:', outcome.msg);
      return;
    }

    // 钱包账户可能还在水合（刷新后扩展回连有几秒延迟）——短暂等待
    // 而不是立刻失败；超时才提示重连。
    const readyAccount = await waitForAccount();
    if (!readyAccount) {
      logger.error('[SitDown] No Starknet account available (waited 6s)');
      addMessage('钱包账户未就绪：请在钱包扩展中确认已连接后重试');
      return;
    }

    // ----- Starknet 买入（一次性）：私密路径优先（Plan B），公开路径回退 -----
    addMessage('Submitting the STRK20 buy-in...');
    const depositResult = await submitBuyIn(readyAccount, amount);
    let depositTxHashUsed: string | undefined;
    if (!depositResult.success) {
      const failMsg = depositResult.error || 'Buy-in deposit failed';
      logger.error('[SitDown] vault.deposit failed:', failMsg);
      // dev 构建降级：钱包层签名/审查失败（如 Argent 云审查不可达
      // SIMULATE_AND_REVIEW_FAILED——扩展需访问 cloud.argent-api.com）时，
      // 允许无链上凭证入座：服务端 SIT_DOWN_V2 仅在携带 deposit_tx_hash
      // 时核验（handlers.rs），dev 模式缺省即放行。生产构建不提供此退路。
      const devFallback =
        import.meta.env.DEV &&
        window.confirm(
          `链上买入失败：${failMsg}\n\n` +
            '开发模式：跳过链上买入直接入座？（不产生真实链上交易，筹码按 dev 余额入账）',
        );
      if (!devFallback) {
        addMessage(`Sit down failed: ${failMsg}`);
        return;
      }
      addMessage('Dev fallback: 跳过链上买入入座（无 deposit 凭证）');
      depositTxHashUsed = undefined;
    } else {
      logger.log('[SitDown] PokerVault deposit tx:', depositResult.hash);
      depositTxHashUsed = depositResult.hash;
    }

    // P1-2 会话委托：与买入同笔登记的会话交易公钥在此声明（服务端经
    // vault active_session_tx_pk view 逐字节对拍，通过后成为座位 VM
    // 签名验证锚）。wasm 缺失时为 undefined，服务端过渡期 fail-open。
    const sessionTxPk = await ensureTxSessionPkHex();
    if (!sessionTxPk) {
      logger.warn('[SitDown] session tx pk unavailable — joining without delegation');
    }

    // ----- 入座（带重试）：bots 无限循环手牌时 deck 每 ~20s 变更一层，
    // 新玩家取牌组→生成证明→提交的间隙可能撞上变更（Invalid remask proof）。
    // 服务器把 join 失败经 error 事件回传，客户端据此自动重取牌组重试。
    const MAX_ATTEMPTS = 3;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      // 每次尝试重新拉取最新 table/deck 状态
      let table = currentTableRef.current;
      try {
        const resp = await httpClient.get<Table>(`/tables/${tableId}`);
        if (resp.data) table = resp.data;
      } catch (e) {
        logger.warn('[SitDown] failed to fetch fresh table state, using local cache:', e);
      }
      const deckEncrypted = table.shuffleState?.deck_encrypted || table.deck?.cards;
      if (!deckEncrypted || deckEncrypted.length === 0) {
        logger.error('[SitDown] No deck_encrypted available');
        addMessage('Cannot sit down: no encrypted deck');
        return;
      }
      // 入座统一走 plain join（对齐 texas_poker_move main 的 join 语义）：
      // 仅提交 pk ownership proof，不动牌组——牌局中替换牌组会让在场玩家
      // 解不出手牌。玩家以 waiting 身份入座，reset_for_next_hand 后在下一手
      // 参与 start_preflop_shuffle 洗牌轮（SHUFFLE_NOTICE 流程既有实现）。
      // deck 竞态与 Invalid remask proof 由此彻底消除。
      let pkProof: unknown;
      try {
        const proofRaw = wrapCryptoOp(() => keys.generate_pk_proof(), 'generate_pk_proof') as string | object;
        pkProof = typeof proofRaw === 'string' ? JSON.parse(proofRaw) : proofRaw;
      } catch (e) {
        const err = e as Error;
        logger.error('[SitDown] pk proof generation failed:', err);
        addMessage(`Sit down failed: ${err.message || err}`);
        return;
      }

      // 提交并在窗口期内监听服务器回传的入座失败（deck 竞态可重试）。
      // 无错误回执即视为入座已受理（与既往乐观行为一致）。
      const outcome = await new Promise<{ failed: boolean; msg: string; retryable?: boolean } | null>((resolve) => {
        let settled = false;
        const onErr = (data: { msg?: string; action?: string; retryable?: boolean }) => {
          if (data?.action !== 'sit_down' || settled) return;
          settled = true;
          socket?.off('error', onErr);
          resolve({ failed: true, msg: data.msg ?? 'sit down rejected', retryable: data.retryable });
        };
        socket?.on('error', onErr);
        socket?.emit(SIT_DOWN_V2, {
          token,
          tableId,
          seatId: seatIdNum,
          amount,
          pkHex,
          pkProof,
          depositTxHash: depositTxHashUsed,
          sessionTxPk: sessionTxPk ?? undefined,
        });
        setTimeout(() => {
          if (!settled) {
            settled = true;
            socket?.off('error', onErr);
            resolve(null);
          }
        }, 6000);
      });

      if (outcome === null) {
        addMessage('Joined table and shuffled successfully');
        logger.log('[SitDown] join accepted (no error within window)');
        return;
      }
      const busyRetry = /洗牌|牌局进行中/.test(outcome.msg);
      if (!busyRetry && !/remask|shuffle|c1|deck|mismatch/i.test(outcome.msg)) {
        addMessage(`Sit down failed: ${outcome.msg}`);
        logger.error('[SitDown] join rejected:', outcome.msg);
        return;
      }
      logger.warn(`[SitDown] join deferred (attempt ${attempt}/${MAX_ATTEMPTS}): ${outcome.msg} — retrying`);
      addMessage(`桌面忙，正在自动重试入座（${attempt}/${MAX_ATTEMPTS}）…`);
      await new Promise((r) => setTimeout(r, 3000));
    }
  };

  const rebuy = (tableId: string, seatIdNum: number, amount: number) => {
    socket?.emit(REBUY, { tableId, seatId: seatIdNum, amount });
  };

  const standUp = async () => {
    if (!currentTableRef.current) return;
    const table = currentTableRef.current;

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      logger.error('[StandUp] No player keys available');
      return;
    }

    const deckEncrypted = table.shuffleState?.deck_encrypted || table.deck?.cards;

    // 没有 deck（例如从未洗牌的座位）：直接走简单 stand up
    if (!deckEncrypted || deckEncrypted.length === 0) {
      logger.warn('[StandUp] No deck_encrypted, falling back to simple stand up');
      socket?.emit(STAND_UP, { tableId: table.id, pkHex, leaveRound: null });
      return;
    }

    // Starknet 模式：离桌证明走 socket 由后端验证（per-hand 操作全部离链，
    // 链上只涉及 PokerVault 的筹码出入）。
    let outputCardsJson: string;
    let leaveProofJson: string;
    let inputCards: unknown;
    try {
      const deckEncryptedJson = JSON.stringify(deckEncrypted);
      // Bug 修复（离开不亮牌）：剥层会公开 sk·c1（= 自己对各牌的 reveal
      // token），必须排除自己手牌的槽位。通过手牌密文 c1（reveal 生命周期
      // 不变）与牌组密文 c1 匹配定位槽位。验证方从发牌状态推导同一集合。
      const myHoleC1s = ownHoleC1Set();
      const excludedIndices: number[] = deckEncrypted
        .map((card: unknown, idx: number) => {
          const c1 = extractC1(card);
          return c1 && myHoleC1s.has(c1) ? idx : -1;
        })
        .filter((i: number) => i >= 0);
      const leaveResult = wrapCryptoOp(() => {
        const result = keys.leave_game(deckEncryptedJson, JSON.stringify(excludedIndices));
        if (!result) throw new Error('leave_game returned null');
        return typeof result === 'string' ? JSON.parse(result) : result;
      }, 'leave_game') as { input_cards: unknown; output_cards: unknown; leave_proof: unknown };

      inputCards = leaveResult.input_cards;
      outputCardsJson = JSON.stringify(leaveResult.output_cards);
      leaveProofJson = JSON.stringify(leaveResult.leave_proof);
    } catch (e) {
      const err = e as Error;
      logger.error('[StandUp] leave_game failed:', e);
      throw err;
    }

    await new Promise<void>((resolve, reject) => {
      let settled = false;

      const cleanup = () => {
        clearTimeout(timer);
        socket?.off(TABLE_UPDATED, onTableUpdated);
        socket?.off('error', onError);
      };

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanup();
        logger.warn('[StandUp] Timed out waiting for server response');
        reject(new Error('Stand up timed out waiting for server response'));
      }, STAND_UP_TIMEOUT_MS);

      // Server removes player and broadcasts TABLE_UPDATED
      const onTableUpdated = (data: TableUpdatedPayload) => {
        if (!data?.table) return;
        // Check if this player is no longer seated
        const stillSeated = pkHex
          ? Object.values(data.table.seats || {}).some(
              (seat: Seat) => seat.player?.pkHex === pkHex,
            )
          : false;
        if (!stillSeated) {
          if (settled) return;
          settled = true;
          cleanup();
          logger.log('[StandUp] Leave confirmed via TABLE_UPDATED');
          resolve();
        }
      };

      // Server emits error event on proof verification failure
      const onError = (data: { action?: string; msg?: string }) => {
        if (data?.action !== 'leave_with_proof_verified') return;
        if (settled) return;
        settled = true;
        cleanup();
        reject(new Error(data?.msg || 'Stand up failed on server'));
      };

      socket?.on(TABLE_UPDATED, onTableUpdated);
      socket?.on('error', onError);

      socket?.emit(STAND_UP, {
        tableId: table.id,
        pkHex,
        leaveRound: {
          input_cards: inputCards,
          output_cards: JSON.parse(outputCardsJson),
          leave_proof: JSON.parse(leaveProofJson),
        },
      });
    });
  };

  // #16 抗审查：动作以牌局 SK 签名后发出（wasm 不可用时回退未签名）。
  // sk 取值必须带 getPlayerKeys() 兜底（与 sitDown 等路径一致）：playerKeys
  // prop 为 null 时签名静默退化 → 服务端留不下签名 → snip36 递归证明
  // "no signed actions"（2026-09-07 线上）。
  const actionSkHex = () =>
    (playerKeys ?? getPlayerKeys())?.get_sk_hex?.() ?? null;

  const fold = () => {
    const t = currentTableRef?.current;
    if (!t || !socket) return;
    void (async () => {
      const sig = await signTableAction(actionSkHex(), t.id, (t.shuffleState?.hand_id ?? t.handId), 'fold');
      socket?.emit(FOLD, { tableId: t.id, ...sigToPayloadFields(sig) });
    })();
  };

  const check = () => {
    const t = currentTableRef?.current;
    if (!t || !socket) return;
    void (async () => {
      const sig = await signTableAction(actionSkHex(), t.id, (t.shuffleState?.hand_id ?? t.handId), 'check');
      socket?.emit(CHECK, { tableId: t.id, ...sigToPayloadFields(sig) });
    })();
  };

  const call = () => {
    const t = currentTableRef?.current;
    if (!t || !socket) return;
    void (async () => {
      const sig = await signTableAction(actionSkHex(), t.id, (t.shuffleState?.hand_id ?? t.handId), 'call');
      socket?.emit(CALL, { tableId: t.id, ...sigToPayloadFields(sig) });
    })();
  };

  const raise = (amount: number) => {
    const t = currentTableRef?.current;
    if (!t || !socket) return;
    void (async () => {
      const sig = await signTableAction(actionSkHex(), t.id, (t.shuffleState?.hand_id ?? t.handId), 'raise', amount);
      socket?.emit(RAISE, { tableId: t.id, amount, ...sigToPayloadFields(sig) });
    })();
  };

  const sittingOut = () => {
    currentTableRef &&
      currentTableRef.current &&
      seatId != null &&
      socket?.emit(SITTING_OUT, { tableId: currentTableRef.current.id, seatId });
  };

  const sittingIn = () => {
    currentTableRef &&
      currentTableRef.current &&
      seatId != null &&
      socket?.emit(SITTING_IN, { tableId: currentTableRef.current.id, seatId });
  };

  const expelInitiate = (tableId: string, targetPlayerPk: string) => {
    socket?.emit(RECONSTRUCT_INITIATE, { tableId, targetPlayerPk });
  };

  return {
    joinTable,
    leaveTable,
    sitDown,
    rebuy,
    standUp,
    fold,
    check,
    call,
    raise,
    sittingOut,
    sittingIn,
    expelInitiate,
    showFoldLeaveConfirm,
    confirmFoldLeave,
    cancelFoldLeave,
    cancelDeferredLeave,
  };
};