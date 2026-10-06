import { useEffect, useRef } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { Socket } from 'socket.io-client';
import type { Card, CryptoEvent, GameMessage, Table, ShuffleState } from '../../types/game';
import {
  TABLE_JOINED,
  TABLE_LEFT,
  TABLE_UPDATED,
  LEAVE_DEFERRED,
  SHUFFLE_NOTICE,
  SHUFFLE_SUBMIT,
  RECONSTRUCT_NOTICE,
  RECONSTRUCT_SUBMIT,
  RECONSTRUCT_RESULT,
  REVEAL_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
  REDEAL_NOTICE,
  REDEAL_RESULT,
  REDEAL_REQUEST,
  CRYPTO_EVENT,
} from '../../pokergame/actions';
import {
  ShuffleNoticeData,
  RevealNoticeData,
  HandRevealResultData,
  CommunityRevealResultData,
  ReconstructNoticeData,
  ReconstructSubmitPayload,
  TableUpdatedPayload,
  TableJoinedPayload,
  TableLeftPayload,
  HandRevealReturn,
  ShuffleHandleResult,
} from './gameInternal';
import { logger } from '../../helpers/logger';
import { PlayerStorage } from '../player/playerStorage';
import { observeServerSeq } from './actionSigning';
import { useContentContext } from '../content/contentContext';
import { useContext } from 'react';
import authContext from '../auth/authContext';

export interface UseGameSocketParams {
  socket: Socket | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  setCurrentTable: (table: Table | null) => void;
  setMessages: Dispatch<SetStateAction<GameMessage[]>>;
  setDecryptedHandCards: Dispatch<SetStateAction<string[]>>;
  setCommunityCards: Dispatch<SetStateAction<Card[]>>;
  setKickNotification: (notification: string | null) => void;
  setCryptoEvents: Dispatch<SetStateAction<CryptoEvent[]>>;
  setLeaveDeferred: Dispatch<SetStateAction<boolean>>;
  pkHex: string | null;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  handleShuffleNotice: (data: ShuffleNoticeData) => Promise<ShuffleHandleResult | null>;
  handleRevealNotice: (data: RevealNoticeData) => Promise<void>;
  handleReconstructNotice: (data: ReconstructNoticeData) => Promise<ReconstructSubmitPayload | void>;
  handleHandRevealResult: (data: HandRevealResultData) => HandRevealReturn | null;
  handleCommunityRevealResult: (data: CommunityRevealResultData) => void;
  resetRevealDedup: () => void;
  stopActionLoading: () => void;
  /** 洗牌 in-flight 标记（与 useCryptoOperations 共享）：fallback 据此把同一轮让位给直推路径。 */
  shuffleLoadingRef: MutableRefObject<boolean>;
}

function translateKickReason(reason: string): string {
  const lower = reason.toLowerCase();
  let core: string;
  if (lower.includes('shuffle')) {
    core = 'shuffle 超时';
  } else if (lower.includes('reveal')) {
    core = 'reveal 超时';
  } else if (lower.includes('reconstruct')) {
    core = 'reconstruct 超时';
  } else {
    core = reason;
  }
  return `你因 ${core} 被移出牌桌`;
}

const BETTING_ACTIONS = new Set(['fold', 'check', 'call', 'raise']);

export const useGameSocket = (params: UseGameSocketParams): void => {
  const {
    socket,
    addMessage,
    currentTableRef,
    setCurrentTable,
    setMessages,
    setDecryptedHandCards,
    setCommunityCards,
    setKickNotification,
    setCryptoEvents,
    setLeaveDeferred,
    pkHex,
    leaveTable,
    handleShuffleNotice,
    handleRevealNotice,
    handleReconstructNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    resetRevealDedup,
    stopActionLoading,
    shuffleLoadingRef,
  } = params;
  const { walletAddress } = useContext(authContext)!;
  const { getLocalizedString } = useContentContext();

  // TABLE_UPDATED shuffle fallback 去重：同一 shuffle 轮（phase + 已完成人数）
  // 只补交一次，防止重复广播触发重复洗牌提交。
  const shuffleFallbackDoneRef = useRef<{ phase: string; completed: number } | null>(null);
  // SHUFFLE_NOTICE 直推去重（纵深防御，2026-09-07）：服务端事件队列与直接
  // 调用双通道曾同毫秒双发同态通知 → 客户端双重洗牌提交（第二次被
  // "Shuffle not active" 拒绝）。签名 = 当前洗牌者 + 首张密牌 c1：状态真变
  // 必改签名；同签名 250ms 内视为重复，忽略。
  const lastShuffleNoticeRef = useRef<{ sig: string; at: number } | null>(null);
  // TABLE_UPDATED reconstruct fallback 去重：同一 reconstruct 轮（coefficient + pending 数）只补交一次。
  const reconstructFallbackKeyRef = useRef<string | null>(null);

  useEffect(() => {
    // pagehide 取代已废弃的 unload（ unload 在移动端/前进后退缓存下不可靠，
    // pagehide 是标准替代，导航与关页都会触发；'close' 并非 window 事件）。
    // 真实路由离开 /play 的离桌由 GameState 的 useLocation 路由守卫负责
    // （isUnmountingRef cleanup 模式在 StrictMode 下无法区分伪卸载，已移除）。
    const onUnload = () => leaveTable(false, pkHex || undefined, true);
    window.addEventListener('pagehide', onUnload);

    if (socket) {
      (window as unknown as Record<string, unknown>).__sockDebug = {
        reg: Date.now(),
        sid: (socket as unknown as { id?: string }).id ?? null,
      };
      // 围观者/重连者的房间状态同步（docs/design/SETTLEMENT_PRIVACY_PLAN.md 修复项）：
      // 公共牌、亮牌清理、winMessage 都以服务器 TABLE_UPDATED 为准补齐——
      // 仅靠事件流（COMMUNITY_REVEAL_RESULT 等）会让中途进桌的围观者看不到。
      const lastWinMessagesRef = { current: [] as string[] };
      socket.on(TABLE_UPDATED, ({ table, message, from, readableCards, deckPlaintext }: TableUpdatedPayload) => {
        (window as unknown as Record<string, unknown>).__sockDebug = {
          ...(window as unknown as Record<string, unknown>).__sockDebug as object,
          tu: Date.now(),
          phase: (table as { roundState?: string }).roundState,
        };
        logger.log(TABLE_UPDATED, table, message, from);
        if (table.roundState === 'waiting') {
          // 注意：结算完成后服务端立即回 waiting（并非下一手开始才回），
          // 这里只做 dedup 重置——自己的底牌保留到下一手 SHUFFLE_NOTICE
          // 才清空，否则摊牌/结算画面上自己的牌会消失（2026-09-25 线上）。
          resetRevealDedup();
        }
        // 注意：本手结束（handOver）不清自己的底牌——摊牌比牌阶段正是
        // 需要看牌的时刻（页脚英雄卡 + 牌型标注）；底牌在下一手开始时
        // 由 waiting 快照 / SHUFFLE_NOTICE 清空。
        // 公共牌以服务器 board 为准同步（错过 reveal 事件的围观者由此补上）
        if (Array.isArray(table.board)) {
          setCommunityCards(table.board as Card[]);
        }
        // winMessage 保持显示直到新一手开始（waiting 之后的新手牌清空）
        const winMsgs = (table as { winMessages?: string[] }).winMessages;
        if (Array.isArray(winMsgs) && winMsgs.length > 0) {
          lastWinMessagesRef.current = winMsgs;
        } else if (
          lastWinMessagesRef.current.length > 0 &&
          table.roundState !== 'waiting' && table.roundState !== 'showdown'
        ) {
          lastWinMessagesRef.current = [];
        }
        if (lastWinMessagesRef.current.length > 0 && !(winMsgs?.length)) {
          (table as { winMessages?: string[] }).winMessages = lastWinMessagesRef.current;
        }
        setCurrentTable(table);
        logger.log("table updated:", table);
        message && addMessage(message);

        // 重连单次快照：私人可读底牌随 TABLE_UPDATED 直达（错过
        // HAND_REVEAL_RESULT 即永久不可见，2026-09-08 线上），走同一
        // 条解密/锚点路径。手已结束/未发牌时快照不带牌，自然跳过。
        if (Array.isArray(readableCards) && readableCards.length > 0 && !table.handOver) {
          const currentPkHex = pkHex || PlayerStorage.getPk();
          if (currentPkHex) {
            const redealInfo = handleHandRevealResult({
              tableId: table.id,
              playerPk: currentPkHex,
              readableCards,
              deckPlaintext,
            });
            if (redealInfo) {
              addMessage(`重连快照解密失败 ${redealInfo.failedCards?.length || 0} 张牌`);
            }
          }
        }

        // Fallback reveal trigger for missed REVEAL_NOTICE
        const revealState = table.revealTokenState;
        const revealPhase = revealState?.phase;
        const isPhaseActive = revealPhase && revealPhase !== 'None' && revealPhase !== '';
        if (revealState && isPhaseActive && pkHex && revealState.pending_players?.includes(pkHex)
            && !revealState.completed_players?.includes(pkHex)) {
          logger.log('[Reveal] TABLE_UPDATED fallback: player in pending, phase=' + revealPhase + ', triggering handleRevealNotice');
          handleRevealNotice({
            table_id: table.id,
            phase: revealPhase,
            pending_players: revealState.pending_players,
            player_assignments: revealState.player_assignments,
          });
        }

        // Fallback reconstruct trigger for missed RECONSTRUCT_NOTICE：
        // 快照 reconstructState 与 RECONSTRUCT_NOTICE 字段一致，轮到我时直接补做。
        const reconstructState = table.reconstructState;
        if (reconstructState && reconstructState.is_active && pkHex
            && Array.isArray(reconstructState.pending_players)
            && reconstructState.pending_players.includes(pkHex)) {
          const recKey = `${reconstructState.context_digest}#${reconstructState.reconstruction_epoch}`;
          if (reconstructFallbackKeyRef.current !== recKey) {
            logger.log('[Reconstruct] TABLE_UPDATED fallback: player in pending, triggering handleReconstructNotice');
            void (async () => {
              const result = await handleReconstructNotice({
                table_id: table.id,
                completed_players: reconstructState.completed_players,
                pending_players: reconstructState.pending_players,
                cards: reconstructState.cards,
                aggregate_pk: reconstructState.aggregate_pk,
                context_digest: reconstructState.context_digest,
                reconstruction_epoch: reconstructState.reconstruction_epoch,
                prior_state_digests: reconstructState.prior_state_digests,
                player_residual_carriers: reconstructState.player_residual_carriers,
              });
              if (result) {
                reconstructFallbackKeyRef.current = recKey;
                socket?.emit(RECONSTRUCT_SUBMIT, result);
              }
            })();
          }
        }

        // Fallback shuffle trigger for missed SHUFFLE_NOTICE（刷新/重连恢复）：
        // 快照的 shuffleState 与 SHUFFLE_NOTICE 携带同样的 current_player_pk /
        // deck_encrypted / aggregate_pk，轮到我洗牌时直接补做。失败（返回 null）
        // 不记 dedup，下一次 TABLE_UPDATED 会重试。
        const shuffleState = table.shuffleState as (ShuffleState & { phase?: string }) | null;
        if (shuffleState && shuffleState.current_player_pk && pkHex
            && shuffleState.current_player_pk === pkHex) {
          const completedCount = Array.isArray(shuffleState.completed_players)
            ? shuffleState.completed_players.length : 0;
          const done = shuffleFallbackDoneRef.current;
          if (!done || done.phase !== (shuffleState.phase || '') || done.completed !== completedCount) {
            // 直推 SHUFFLE_NOTICE 正在处理同一轮（in-flight）时，本轮由直推
            // 负责提交：记 dedup 键并跳过，防止该轮后续同键 TABLE_UPDATED
            // 在直推完成后（in-flight 清零）再次补交 → 双重提交（第二次被
            // 服务端以 "Not current player"/"Shuffle not active" 拒绝）。
            if (shuffleLoadingRef.current) {
              logger.log('[Shuffle] TABLE_UPDATED fallback: direct path in-flight, defer to it (phase=' + shuffleState.phase + ')');
              shuffleFallbackDoneRef.current = { phase: shuffleState.phase || '', completed: completedCount };
            } else {
              logger.log('[Shuffle] TABLE_UPDATED fallback: it is my turn (phase=' + shuffleState.phase + '), triggering handleShuffleNotice');
              void (async () => {
                const result = await handleShuffleNotice({
                  tableId: String(table.id),
                  shuffleState: shuffleState as ShuffleState,
                });
                if (result) {
                  shuffleFallbackDoneRef.current = { phase: shuffleState.phase || '', completed: completedCount };
                  socket?.emit(SHUFFLE_SUBMIT, {
                    table_id: Number(result.tableId),
                    pk_hex: result.pkHex,
                    output_cards: result.shuffleResult.output_cards,
                    shuffle_proof: result.shuffleResult.shuffle_proof ?? undefined,
                    mask_and_shuffle_round: result.maskAndShuffleRound ?? undefined,
                  });
                  addMessage(`Shuffle submitted (${result.shuffleResult.output_cards.length} cards)`);
                }
              })();
            }
          }
        }
      });

      // #17 动作回执：自己的 accepted/autoAccepted 回执里带服务端分配的
      // seq——据此 ratchet 本地计数器，避免服务端 auto 代打自增后客户端
      // seq 落后、签名有效却被 seq 单调性拒掉（2026-09-08 线上）。
      socket.on('ACTION_RECEIPT', (data: { receipt?: { tableId?: number; playerPk?: string; seq?: number } }) => {
        const r = data?.receipt;
        if (r && typeof r.seq === 'number' && r.playerPk && pkHex && r.playerPk === pkHex) {
          observeServerSeq(r.tableId ?? currentTableRef.current?.id ?? 1, r.seq);
        }
      });

      socket.on(TABLE_JOINED, ({ table, message, from }: TableJoinedPayload) => {
        logger.log(TABLE_JOINED, table, message, from);
        logger.log("table joined:", table);
        // 围观者首次进桌：公共牌/上一手结果从初始快照补齐
        if (Array.isArray(table.board)) {
          setCommunityCards(table.board as Card[]);
        }
        setCurrentTable(table);
      });

      socket.on(TABLE_LEFT, ({ tables, tableId, reason }: TableLeftPayload) => {
        logger.log(TABLE_LEFT, tables, tableId, reason);
        setCurrentTable(null);
        setMessages([]);
        setDecryptedHandCards([]);
        setCommunityCards([]);
        setLeaveDeferred(false);
        if (reason && reason.trim()) {
          setKickNotification(translateKickReason(reason));
        }
      });

      socket.on(LEAVE_DEFERRED, (payload: { tableId: number; reason: string }) => {
        logger.log(LEAVE_DEFERRED, payload);
        setLeaveDeferred(true);
      });

      socket.on(SHUFFLE_NOTICE, async (data: ShuffleNoticeData) => {
        // 双通道去重：同态通知（同洗牌者 + 同首张密牌）250ms 内只处理一次。
        // deck_encrypted 项在 wire 上是 {c1_hex, c2_hex}（ElGamalCiphertextJson；
        // 客户端类型里的 string[][] 是陈旧声明，此处按运行时形状取值）。
        const firstCard = data.shuffleState?.deck_encrypted?.[0] as { c1_hex?: string } | undefined;
        const sig = `${data.shuffleState?.current_player_pk ?? ''}|${firstCard?.c1_hex ?? ''}`;
        const now = Date.now();
        const last = lastShuffleNoticeRef.current;
        if (last && last.sig === sig && now - last.at < 250) {
          logger.log('[Shuffle] duplicate SHUFFLE_NOTICE suppressed (same state within 250ms)');
          return;
        }
        lastShuffleNoticeRef.current = { sig, at: now };
        setCommunityCards([]);
        setDecryptedHandCards([]);
        resetRevealDedup();
        const result = await handleShuffleNotice(data);
        if (result) {
          // 直推已提交本轮 shuffle → 同步 fallback 的 dedup 键：迟到的同轮
          // TABLE_UPDATED 不再触发补交（双重提交会被服务端拒绝并刷日志）。
          const st = data.shuffleState as (ShuffleState & { phase?: string }) | undefined;
          if (st) {
            shuffleFallbackDoneRef.current = {
              phase: st.phase || '',
              completed: Array.isArray(st.completed_players) ? st.completed_players.length : 0,
            };
          }
          logger.log('SHUFFLE_NOTICE shuffle proof', result.shuffleResult.shuffle_proof);
          socket.emit(SHUFFLE_SUBMIT, {
            table_id: Number(result.tableId),
            pk_hex: result.pkHex,
            output_cards: result.shuffleResult.output_cards,
            shuffle_proof: result.shuffleResult.shuffle_proof ?? undefined,
            mask_and_shuffle_round: result.maskAndShuffleRound ?? undefined,
          });
          logger.log(SHUFFLE_SUBMIT, result);
          addMessage(`Shuffle submitted (${result.shuffleResult.output_cards.length} cards)`);
        }
      });

      socket.on(REVEAL_NOTICE, (data: RevealNoticeData) => {
        handleRevealNotice(data);
      });

      socket.on(RECONSTRUCT_NOTICE, async (data: ReconstructNoticeData) => {
        const result = await handleReconstructNotice(data);
        if (result) {
          socket.emit(RECONSTRUCT_SUBMIT, result);
        }
      });

      socket.on(RECONSTRUCT_RESULT, (data: { expelled?: boolean }) => {
        logger.log(RECONSTRUCT_RESULT, data);
        if (data?.expelled) {
          addMessage('Player expelled by vote');
        } else {
          addMessage('construct vote timed out');
        }
      });

      socket.on(HAND_REVEAL_RESULT, (data: HandRevealResultData) => {
        const redealInfo = handleHandRevealResult(data);
        if (redealInfo) {
          socket.emit(REDEAL_REQUEST, {
            tableId: currentTableRef.current?.id,
            playerPk: redealInfo.playerPk,
            failedCardIndices: redealInfo.failedCardIndices,
          });
          addMessage(`Requesting redeal for ${redealInfo.failedCardIndices?.length || 0} failed cards...`);
        }
      });

      socket.on(COMMUNITY_REVEAL_RESULT, (data: CommunityRevealResultData) => {
        handleCommunityRevealResult(data);
      });

      socket.on(REDEAL_NOTICE, (data: RevealNoticeData) => {
        logger.log(REDEAL_NOTICE, data);
        handleRevealNotice(data);
      });

      socket.on(REDEAL_RESULT, (data: HandRevealResultData) => {
        const redealInfo = handleHandRevealResult(data);
        if (redealInfo) {
          addMessage(`Redeal decryption still failed for ${redealInfo.failedCardIndices?.length || 0} cards`);
        } else {
          addMessage('Redeal successful, new cards decrypted');
        }
      });

      socket.on(CRYPTO_EVENT, (data: CryptoEvent) => {
        logger.log(CRYPTO_EVENT, data);
        setCryptoEvents((prev) => {
          const next = [...prev, data];
          return next.length > 100 ? next.slice(next.length - 100) : next;
        });
      });

      // Per-hand poker actions (fold/check/call/raise) flow client-side
      // through the connected Starknet wallet via useAccount() / useSendTransaction.
      // There is no longer a server-pushed ACTION_SIGNING_REQUEST event —
      // chip operations and per-hand actions go through starknet-react hooks
      // directly from the action caller. This keeps the protocol uniform with
      // any future AVNU paymaster or Cartridge controller integration.

      // Global error handling for server-sent errors (e.g. SIT_DOWN_V2 deck
      // out of sync). For betting action errors, close the loading overlay
      // so the player can act again.
      socket.on('error', (data: { code?: string; key?: string; msg?: string; detail?: string; action?: string; table_id?: string }) => {
        // 良性幂等：同一玩家重复提交 reveal token（同账号多浏览器/双触发竞态）
        // 被服务器拒绝属正常现象，首次提交已生效，不作为错误展示。
        if (data?.msg && data.msg.includes('already submitted or not pending')) {
          logger.log('[Socket error] benign duplicate reveal submit:', data.msg);
          return;
        }
        if (data?.code && data.code === 'REVEAL_DUPLICATE') {
          logger.log('[Socket error] benign duplicate reveal submit (code)');
          return;
        }
        // 开发者视角：完整结构化信息进 console（code/detail 用于排障）
        logger.error('[Socket error]', data);
        if (data?.action && BETTING_ACTIONS.has(data.action)) {
          stopActionLoading();
        }
        // i18n：payload.key = locale 文件的稳定键（socket_error_<CODE>）；
        // 本地化缺失时回退服务端 msg，再回退通用文案
        let friendly: string | undefined;
        if (data?.key) {
          const localized = getLocalizedString(data.key);
          if (localized !== data.key) friendly = localized;
        }
        if (!friendly) friendly = data?.msg || '操作失败，请稍候重试';
        addMessage(friendly);
      });
    }
    return () => {
      window.removeEventListener('pagehide', onUnload);
      socket?.off(TABLE_UPDATED);
      socket?.off(TABLE_JOINED);
      socket?.off(TABLE_LEFT);
      socket?.off(LEAVE_DEFERRED);
      socket?.off(SHUFFLE_NOTICE);
      socket?.off(REVEAL_NOTICE);
      socket?.off(RECONSTRUCT_NOTICE);
      socket?.off(RECONSTRUCT_RESULT);
      socket?.off(HAND_REVEAL_RESULT);
      socket?.off(COMMUNITY_REVEAL_RESULT);
      socket?.off(REDEAL_NOTICE);
      socket?.off(REDEAL_RESULT);
      socket?.off(CRYPTO_EVENT);
      socket?.off('error');
      // 离桌触发已迁移：真实路由离开 → GameState 的 useLocation 守卫；
      // 页面关闭/刷新 → 上方 pagehide 监听。cleanup 不再做业务动作
      // （React 18 StrictMode 挂载双执行会调用 cleanup，无法区分伪卸载）。
    };
  }, [socket, handleShuffleNotice, handleRevealNotice, handleReconstructNotice, handleHandRevealResult, handleCommunityRevealResult, resetRevealDedup, stopActionLoading, addMessage, currentTableRef, leaveTable, pkHex, setCommunityCards, setCryptoEvents, setCurrentTable, setDecryptedHandCards, setKickNotification, setLeaveDeferred, setMessages]);
}
