import { useCallback, useRef } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { Socket } from 'socket.io-client';
import type { WasmClientPlayer } from '@linqining/client-wasm';
import { guardRevealAssignment, recordOwnCards } from './revealOwnCardGuard';
import { recordOwnHoleCiphertexts } from './ownHoleCards';
import type { Card, Table } from '../../types/game';
import type { SubmitRevealToken } from '../../api/secretPokerClient';
import {
  SHUFFLE_NOTICE,
  SHUFFLE_SUBMIT,
  REVEAL_NOTICE,
  REVEAL_SUBMIT,
  RECONSTRUCT_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
} from '../../pokergame/actions';
import {
  ShuffleNoticeData,
  ShuffleResult,
  ShuffleHandleResult,
  RevealNoticeData,
  HandRevealResultData,
  HandRevealReturn,
  CommunityRevealResultData,
  ReconstructNoticeData,
  ReconstructSubmitPayload,
  ReconstructResult,
  wrapCryptoOp,
  parseWasmResult,
} from './gameInternal';
import { logger } from '../../helpers/logger';
import { PlayerStorage } from '../player/playerStorage';

export interface UseCryptoOperationsParams {
  socket: Socket | null;
  playerKeys: WasmClientPlayer | null;
  pkHex: string | null;
  getPlayerKeys: () => WasmClientPlayer | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  setShuffleLoading: (value: boolean) => void;
  setRevealLoading: (value: boolean) => void;
  setDecryptedHandCards: Dispatch<SetStateAction<string[]>>;
  setCommunityCards: Dispatch<SetStateAction<Card[]>>;
  shuffleLoadingRef: MutableRefObject<boolean>;
  revealLoadingRef: MutableRefObject<boolean>;
}

export interface UseCryptoOperationsReturn {
  handleShuffleNotice: (data: ShuffleNoticeData) => Promise<ShuffleHandleResult | null>;
  handleRevealNotice: (data: RevealNoticeData) => Promise<void>;
  handleHandRevealResult: (data: HandRevealResultData) => HandRevealReturn | null;
  handleCommunityRevealResult: (data: CommunityRevealResultData) => void;
  handleReconstructNotice: (data: ReconstructNoticeData) => Promise<ReconstructSubmitPayload | void>;
  resetRevealDedup: () => void;
}

/** djb2：dedup 指纹用的廉价字符串哈希（非加密用途）。 */
function djb2Fingerprint(input: string): string {
  let h = 5381;
  for (let i = 0; i < input.length; i++) {
    h = ((h << 5) + h + input.charCodeAt(i)) >>> 0;
  }
  return h.toString(16);
}

/**
 * 用户洗牌置换：Fisher-Yates + `crypto.getRandomValues`（CSPRNG）。
 * 置换在客户端本地生成——洗牌决定权属于用户（z_poker permute 收口）。
 */
export function generatePermutation(n: number): number[] {
  const arr = Array.from({ length: n }, (_, i) => i);
  const buf = new Uint32Array(n);
  crypto.getRandomValues(buf);
  for (let i = n - 1; i > 0; i -= 1) {
    const j = buf[i] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

export const useCryptoOperations = (
  params: UseCryptoOperationsParams,
): UseCryptoOperationsReturn => {
  const {
    socket,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    setShuffleLoading,
    setRevealLoading,
    setDecryptedHandCards,
    setCommunityCards,
    shuffleLoadingRef,
    revealLoadingRef,
  } = params;

  // Resolves the current player keys from state or storage. Returns null when
  // no keys are available — callers keep their existing early-return behavior.
  const getRequiredKeys = useCallback((): WasmClientPlayer | null => {
    return playerKeys || getPlayerKeys();
  }, [playerKeys, getPlayerKeys]);

  // 防止同一 reveal phase 实例的重复 REVEAL_NOTICE 导致重复提交。
  // revealLoadingRef 仅防并发，emit 后立即重置无法阻止同一阶段的顺序重复提交。
  // 此 ref 记录已提交实例的 key + 时间戳，30 秒窗口内同实例的重复通知直接跳过。
  // key 必须是“phase 实例”指纹（phase 名 + assignment 卡集合）：同一手牌的
  // Turn 和 River 两个 CommunityReveal 阶段同名，若只按 phase 名去重，
  // 刷新/重连后补交 Turn token 的客户端会把 30s 内到达的 River 通知也
  // dedup 掉 → River 永远等不到 token → 全桌超时被踢（2026-09-01 线上复现）。
  const revealSubmittedRef = useRef<{ key: string; ts: number } | null>(null);

  const resetRevealDedup = useCallback(() => {
    if (revealSubmittedRef.current) {
      logger.log('[Reveal] resetRevealDedup: clearing previous dedup state', revealSubmittedRef.current);
      revealSubmittedRef.current = null;
    }
  }, []);

  const handleShuffleNotice = useCallback(async (data: ShuffleNoticeData): Promise<ShuffleHandleResult | null> => {
    logger.log(SHUFFLE_NOTICE, data);
    const { tableId, shuffleState } = data;

    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[Shuffle] No player keys available');
      return null;
    }
    logger.log('[SHUFFLE_NOTICE] Current player:', pkHex, keys);
    if (shuffleState.current_player_pk !== pkHex) {
      logger.log('[Shuffle] Not my turn, waiting...');
      return null;
    }

    if (shuffleLoadingRef.current) {
      logger.log('[Shuffle] Already processing a shuffle');
      return null;
    }

    const deckEncrypted = shuffleState.deck_encrypted;
    const aggregatePk = shuffleState.aggregate_pk;

    if (!deckEncrypted || deckEncrypted.length === 0) {
      logger.warn('[Shuffle] No deck_encrypted in shuffle state');
      return null;
    }
    if (!aggregatePk) {
      logger.warn('[Shuffle] No aggregate_pk');
      return null;
    }

    shuffleLoadingRef.current = true;
    setShuffleLoading(true);

    try {
      const deckJson = JSON.stringify(deckEncrypted);

      // needs_join_layer=true（waiting 入座、从未 remask 过的玩家补层）时
      // 必须走 join_game_and_shuffle（remask 自身层 + shuffle）：纯 re_encrypt
      // 会让牌组密文份额与公钥和对不上 → 全桌 decrypt_readable_card 失败、
      // 手牌无法显示（2026-09-01 线上复现）。
      const needsJoinLayer = !!(shuffleState as { needs_join_layer?: boolean }).needs_join_layer;
      const sharePk = (shuffleState as { share_pk?: string }).share_pk;
      if (needsJoinLayer && !sharePk) {
        logger.error('[Shuffle] needs_join_layer=true but no share_pk in notice');
        addMessage('Shuffle failed: missing share_pk for join layer');
        return null;
      }

      // 用户洗牌：置换在客户端本地生成（Fisher-Yates + CSPRNG）——洗牌
      // 决定权属于用户，服务端/库都不再代生成（z_poker permute 收口）。
      const deckLen = deckEncrypted.length;
      const permute = generatePermutation(deckLen);
      const permuteJson = JSON.stringify(permute);
      logger.log('[Shuffle] user permute generated', { deckLen });

      let outputCards: unknown[];
      let shuffleProof: unknown;
      let maskAndShuffleRound: unknown;
      if (needsJoinLayer && sharePk) {
        const joinRaw = wrapCryptoOp(() => {
          const raw = (keys as unknown as {
            join_game_and_shuffle: (deck: string, sharePk: string, permute: string) => string;
          }).join_game_and_shuffle(deckJson, sharePk, permuteJson);
          if (!raw) throw new Error('join_game_and_shuffle returned null');
          return parseWasmResult<{
            pk_hex: string;
            pk_ownership_proof: unknown;
            mask_and_shuffle_round: {
              mask_cards: unknown[];
              output_cards: unknown[];
              remask_proof: unknown;
              shuffle_proof: unknown;
            };
          }>(raw);
        }, 'joinGameAndShuffle');
        outputCards = joinRaw.mask_and_shuffle_round.output_cards;
        maskAndShuffleRound = joinRaw.mask_and_shuffle_round;
        logger.log('[Shuffle] join-layer round built (remask+shuffle)');
      } else {
        const shuffleResult = wrapCryptoOp(() => {
          const result = (keys as unknown as {
            shuffle: (deck: string, aggregatePk: string, permute: string) => string;
          }).shuffle(deckJson, aggregatePk, permuteJson);
          if (!result) throw new Error('Shuffle returned null');
          return parseWasmResult<ShuffleResult>(result);
        }, 'shuffle');

        if (!shuffleResult.output_cards || !Array.isArray(shuffleResult.output_cards)) {
          throw new Error('Invalid shuffle result: missing output_cards');
        }
        outputCards = shuffleResult.output_cards;
        // WASM shuffle 返回完整 BG V2 证明，必须透传给服务端
        // （submit_verified_shuffle 验证必需；此前被丢弃为 undefined，
        // 纯洗牌提交必然被服务端拒绝）。
        shuffleProof = (shuffleResult as unknown as { shuffle_proof?: unknown }).shuffle_proof;
        if (!shuffleProof) {
          throw new Error('Invalid shuffle result: missing shuffle_proof');
        }
      }

      const gameId = String(tableId);
      logger.log(SHUFFLE_SUBMIT, { gameId, pkHex, cardCount: outputCards.length });

      return {
        tableId,
        gameId,
        pkHex,
        shuffleResult: {
          output_cards: outputCards as ShuffleResult['output_cards'],
          shuffle_proof: shuffleProof as ShuffleResult['shuffle_proof'],
        },
        maskAndShuffleRound: maskAndShuffleRound as ShuffleHandleResult['maskAndShuffleRound'],
      };
    } catch (e) {
      const err = e as Error;
      logger.error('[Shuffle] Failed:', e);
      addMessage(`Shuffle failed: ${err.message || e}`);
      return null;
    } finally {
      shuffleLoadingRef.current = false;
      setShuffleLoading(false);
    }
  }, [getRequiredKeys, pkHex, addMessage]);

  const handleRevealNotice = useCallback(async (data: RevealNoticeData): Promise<void> => {
    logger.log(REVEAL_NOTICE, data);
    const { table_id, phase, pending_players, player_assignments } = data;

    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[Reveal] No player keys available');
      return;
    }

    if (!pending_players || !pending_players.includes(pkHex!)) {
      logger.log('[Reveal] Not my turn for reveal');
      return;
    }

    if (revealLoadingRef.current) {
      logger.log('[Reveal] Already processing reveal tokens');
      return;
    }

    const assignments = player_assignments || currentTableRef.current?.revealTokenState?.player_assignments;
    if (!assignments) {
      logger.warn('[Reveal] No player assignments available');
      return;
    }

    const myAssignment = assignments[pkHex!];
    if (!myAssignment) {
      logger.warn('[Reveal] No assignment found for my pk');
      return;
    }

    let cardsForPhase: unknown[] = [];
    const handCards = myAssignment.hand_cards || myAssignment.hand_card;
    let rawHandCards: unknown[] = [];
    if (handCards) {
      rawHandCards = handCards.map((c: { encrypted_card?: string } | string) =>
        typeof c === 'string' ? c : c.encrypted_card || c
      );
      cardsForPhase = [...rawHandCards];
    }
    const communityCards = myAssignment.community_cards || myAssignment.community_card;
    if (communityCards && communityCards.length > 0) {
      for (const cc of communityCards) {
        cardsForPhase.push(typeof cc === 'string' ? cc : cc.encrypted_card || cc);
      }
    }

    if (cardsForPhase.length === 0) {
      logger.warn('[Reveal] No cards assigned');
      return;
    }

    // 防止同一 phase 实例的重复 REVEAL_NOTICE 导致重复提交（30 秒窗口）。
    // 竞态修复：REVEAL_NOTICE 与 TABLE_UPDATED fallback 会在同一广播批次内
    // 并发触发本 handler，若在提交成功后才写 dedup（旧实现），两次调用都会
    // 通过检查 → 第二次提交被服务器拒为 "already submitted or not pending"。
    // 这里在进入时立即占坑（先写 key 再做后续异步工作）。
    // key 用 phase 实例指纹：Turn/River 的 CommunityReveal 同名但卡集合不同，
    // 只按 phase 名去重会把下一个 street 的通知也 skip 掉（刷新恢复场景）。
    const now = Date.now();
    const dedupKey = `${phase}#${cardsForPhase.length}#${djb2Fingerprint(JSON.stringify(cardsForPhase))}`;
    const lastSubmit = revealSubmittedRef.current;
    if (lastSubmit && lastSubmit.key === dedupKey && now - lastSubmit.ts < 30_000) {
      logger.warn(`[Reveal] DEDUP SKIP: key=${dedupKey} last_ts=${lastSubmit.ts} now=${now} elapsed=${now - lastSubmit.ts}ms < 30000ms — if this is a NEW hand, resetRevealDedup should have been called`);
      return;
    }
    if (lastSubmit) {
      logger.log(`[Reveal] DEDUP PASS: prev_key=${lastSubmit.key} new_key=${dedupKey} elapsed=${now - lastSubmit.ts}ms`);
    }
    revealSubmittedRef.current = { key: dedupKey, ts: now };

    // P0.1/P0.4 reveal 编排守卫（Plan D）：非 ShowdownReveal 阶段，
    // assignment 中的手牌卡命中自有手牌 marker（HAND_REVEAL_RESULT 建立
    // 的 c1 锚点）即拒绝出 token —— 阻断恶意服务器借客户端之手集齐
    // N 份解密份额的主动偷看路径。无锚点时保守拒绝手牌类 assignment。
    const rawCommunityCards: unknown[] = (communityCards || []).map(
      (cc: { encrypted_card?: string } | string) => (typeof cc === 'string' ? cc : cc.encrypted_card || cc)
    );
    const guard = guardRevealAssignment(rawHandCards, rawCommunityCards, phase);
    if (guard.blocked.length > 0) {
      logger.error(
        `[Reveal] GUARD: ${guard.blocked.length} card(s) in my ${phase} assignment match MY OWN hole cards — ` +
          `refusing to surrender decryption shares for them. Server orchestration is hostile or buggy.`
      );
      addMessage(
        `安全守卫：检测到 ${phase} 编排中混入你自己的手牌，已拒绝出 ${guard.blocked.length} 个 token（防偷看保护）`
      );
    }
    if (guard.conservativelyBlocked) {
      logger.warn(
        `[Reveal] GUARD: no own-card anchors established yet (no HAND_REVEAL_RESULT) — ` +
          `conservatively refusing hand-card tokens for phase=${phase}`
      );
      addMessage(`安全守卫：未建立手牌锚点，保守拒绝 ${phase} 的手牌 token 提交`);
    }
    cardsForPhase = guard.allowed;

    if (cardsForPhase.length === 0) {
      logger.warn('[Reveal] All cards blocked by guard; nothing to submit');
      return;
    }

    revealLoadingRef.current = true;
    setRevealLoading(true);

    try {
      const cardJson = JSON.stringify(cardsForPhase);
      const tokens = wrapCryptoOp(() => {
        const tokensRaw = keys.batch_generate_reveal_token(cardJson);
        if (!tokensRaw) throw new Error('batch_generate_reveal_token returned null');
        const parsed = parseWasmResult<unknown[]>(tokensRaw);
        if (!Array.isArray(parsed) || parsed.length === 0) {
          throw new Error('Invalid or empty tokens returned');
        }
        return parsed;
      }, 'batchGenerateRevealToken');

      socket?.emit(REVEAL_SUBMIT, {
        tableId: Number(table_id),
        pkHex: pkHex!,
        revealTokens: tokens as SubmitRevealToken[],
      });
      revealSubmittedRef.current = { key: dedupKey, ts: Date.now() };
      logger.log('[Reveal] Submitted tokens:', { gameId: table_id, pkHex, tokens });

      addMessage(`Reveal ${phase}: ${tokens.length} tokens submitted`);
    } catch (e) {
      const err = e as Error;
      logger.error('[Reveal] Failed:', e);
      addMessage(`Reveal token failed: ${err.message || e}`);
    } finally {
      revealLoadingRef.current = false;
      setRevealLoading(false);
    }
  }, [socket, getRequiredKeys, pkHex, addMessage]);

  const handleHandRevealResult = useCallback((data: HandRevealResultData): HandRevealReturn | null => {
    logger.log(HAND_REVEAL_RESULT, data);
    const { tableId, playerPk, readableCards, deckPlaintext } = data;

    if (!readableCards || !Array.isArray(readableCards) || readableCards.length === 0) {
      logger.warn('[HandReveal] No readable cards in payload');
      return null;
    }

    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[HandReveal] No player keys available for decryption');
      return null;
    }

    const currentPkHex = pkHex || PlayerStorage.getPk();
    if (playerPk !== currentPkHex) {
      logger.warn('[HandReveal] playerPk mismatch, ignoring:', { playerPk, currentPkHex });
      return null;
    }
    // 底牌数量硬上限（德扑 = 2）。服务端异常路径若下发多于 2 张，只取前 2 张
    // 并告警，防止"手牌不限"透出到 UI。
    const MAX_HOLE_CARDS = 2;
    const cappedCards = readableCards.length > MAX_HOLE_CARDS ? readableCards.slice(0, MAX_HOLE_CARDS) : readableCards;
    if (cappedCards.length !== readableCards.length) {
      logger.error(`[HandReveal] payload carried ${readableCards.length} hole cards (max ${MAX_HOLE_CARDS}) — capped`);
    }
    const decFailedCards: unknown[] = [];
    const decrypted: string[] = [];
    for (let i = 0; i < cappedCards.length; i++) {
      const card = cappedCards[i];
      const ctJson = JSON.stringify(card);
      const deckPlaintextJson = JSON.stringify(deckPlaintext);
      try {
        const result = wrapCryptoOp(() => {
          logger.log('[HandReveal] Decrypting card:', ctJson);
          const decryptedStr = keys.decrypt_readable_card(ctJson, deckPlaintextJson);
          if (!decryptedStr) throw new Error('decrypt_readable_card returned null');
          return decryptedStr;
        }, 'decrypt_readable_card');
        logger.log('[HandReveal] Decrypted card:', result);
        decrypted.push(result);
      } catch (e) {
        decFailedCards.push(card);
        const err = e as Error;
        logger.error('[HandReveal] Decryption failed:', e);
        addMessage(`Hand reveal decryption failed: ${err.message || e}`);
        continue;
      }
    }
    if (decFailedCards.length > 0) {
      addMessage(`Hand reveal decryption failed for ${decFailedCards.length} cards`);
      return { failedCards: decFailedCards, playerPk: currentPkHex };
    } else {
      // P0.1 锚点建立：这些密文确认是自己的手牌，记录 marker 供 reveal
      // 编排守卫比对（非 ShowdownReveal 阶段拒绝为自己的手牌出 token）。
      const markerCount = recordOwnCards(readableCards);
      if (markerCount > 0) {
        logger.log(`[HandReveal] Recorded ${markerCount} own-card guard marker(s)`);
      }
      // 离开/弃牌剥层排除集的锚点（c1 不变，见 ownHoleCards.ts）。
      recordOwnHoleCiphertexts(readableCards);
      setDecryptedHandCards(decrypted);
      addMessage(`Hand revealed: ${decrypted.length} cards decrypted`);
      return null;
    }
  }, [getRequiredKeys, pkHex, addMessage]);

  const handleCommunityRevealResult = useCallback((data: CommunityRevealResultData): void => {
    logger.log(COMMUNITY_REVEAL_RESULT, data);
    const { tableId, communityCards: cards } = data;

    if (!cards || !Array.isArray(cards) || cards.length === 0) {
      logger.warn('[CommunityReveal] No community cards in payload');
      return;
    }

    // 公共牌数量硬上限（德扑 = 5）。服务端异常路径若下发多于 5 张，只取前 5 张
    // 并告警，防止"公共牌不限"透出到 UI。
    const MAX_COMMUNITY_CARDS = 5;
    const capped = cards.length > MAX_COMMUNITY_CARDS ? cards.slice(0, MAX_COMMUNITY_CARDS) : cards;
    if (capped.length !== cards.length) {
      logger.error(`[CommunityReveal] payload carried ${cards.length} community cards (max ${MAX_COMMUNITY_CARDS}) — capped`);
    }

    setCommunityCards(capped);
    addMessage(`Community cards revealed: ${capped.length} cards`);
  }, [addMessage]);

  const handleReconstructNotice = useCallback(async (data: ReconstructNoticeData): Promise<ReconstructSubmitPayload | void> => {
    logger.log(RECONSTRUCT_NOTICE, data);
    const { table_id, completed_players, pending_players, cards, aggregate_pk, context_digest, reconstruction_epoch, prior_state_digests, player_residual_carriers } = data;
    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[Reconstruct] No player keys available for decryption');
      return;
    }

    if (!pending_players || !pending_players.includes(pkHex!)) {
      logger.log('[Reconstruct] Not my turn for reconstruct');
      return;
    }

    const myCarriers = player_residual_carriers?.[pkHex!];
    if (!myCarriers || !myCarriers.residual_carriers || myCarriers.residual_carriers.length === 0) {
      logger.warn('[Reconstruct] No residual carriers assigned for my pk');
      return;
    }

    const priorStateDigest = prior_state_digests?.[pkHex!];
    if (!priorStateDigest) {
      logger.warn('[Reconstruct] No prior state digest assigned for my pk');
      return;
    }

    try {
      const originCardsJson = JSON.stringify(cards);
      const residualCarriersJson = JSON.stringify(myCarriers.residual_carriers);

      const result = wrapCryptoOp(() => {
        const resultRaw = keys.reconstruct(
          originCardsJson,
          residualCarriersJson,
          context_digest,
          BigInt(reconstruction_epoch),
          priorStateDigest,
          aggregate_pk,
        );
        if (!resultRaw) throw new Error('reconstruct returned null');
        return parseWasmResult<ReconstructResult>(resultRaw);
      }, 'reconstruct');

      logger.log('RECONSTRUCT_NOTICE statement/proof', result);
      logger.log('[Reconstruct] Result:', result);
      addMessage(`Reconstruct submitted`);
      return {
        table_id,
        pk_hex: pkHex,
        statement: result.statement,
        proof: result.proof,
      } as ReconstructSubmitPayload;
    } catch (e) {
      const err = e as Error;
      logger.error('[Reconstruct] Failed:', e);
      addMessage(`Reconstruct failed: ${err.message || e}`);
    }
  }, [getRequiredKeys, pkHex, addMessage]);

  return {
    handleShuffleNotice,
    handleRevealNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    handleReconstructNotice,
    resetRevealDedup,
  };
};
