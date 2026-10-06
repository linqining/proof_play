import type { Card, ShuffleState, Table } from '../../types/game';
import { logger } from '../../helpers/logger';

export interface ShuffleNoticeData {
  tableId: string;
  shuffleState: ShuffleState;
}

export interface ShuffleResult {
  output_cards: string[][];
  shuffle_proof: unknown;
}

export interface ShuffleHandleResult {
  tableId: string;
  gameId: string;
  pkHex: string | null;
  shuffleResult: ShuffleResult;
  /** join 语义洗牌（waiting 入座玩家补层）：needs_join_layer=true 时携带，
   *  SHUFFLE_SUBMIT 需附带 mask_and_shuffle_round 供服务端验证 remask 层。 */
  maskAndShuffleRound?: {
    mask_cards: unknown[];
    output_cards: unknown[];
    remask_proof: unknown;
    shuffle_proof: unknown;
  };
}

export interface RevealNoticeData {
  table_id: string;
  phase: string;
  pending_players: string[];
  player_assignments?: Record<string, {
    hand_cards?: Array<{ encrypted_card: string } | string>;
    community_cards?: Array<{ encrypted_card: string } | string>;
    hand_card?: Array<{ encrypted_card: string } | string>;
    community_card?: Array<{ encrypted_card: string } | string>;
  }>;
}

export interface HandRevealResultData {
  tableId: string;
  playerPk: string;
  readableCards: unknown[];
  deckPlaintext: unknown;
}

export interface CommunityRevealResultData {
  tableId: string;
  communityCards: Card[];
}

export interface ReconstructNoticeData {
  table_id: string;
  completed_players: string[];
  pending_players: string[];
  cards: unknown[];
  /** 桌 epoch 聚合公钥（statement 绑定用）。 */
  aggregate_pk: string;
  /** 应用域摘要（statement.context_digest 回填用）。 */
  context_digest: string;
  /** 本轮 reconstruct epoch（statement.reconstruction_epoch 回填用）。 */
  reconstruction_epoch: number;
  /** 玩家 → 上一轮 residual-carrier 状态摘要（statement.prior_state_digest 回填用）。 */
  prior_state_digests?: Record<string, string>;
  player_residual_carriers?: Record<string, {
    residual_carriers: unknown[];
  }>;
}

export interface TableUpdatedPayload {
  table: Table;
  message?: string;
  from?: string;
  /** 重连单次快照：自己的可读底牌 + 牌组明文（仅重连定向推送携带；
   * 形状与 HandRevealResultData 同源，走同一条解密路径）。 */
  readableCards?: unknown[];
  deckPlaintext?: string[];
}

export interface TableJoinedPayload {
  table: Table;
  message?: string;
  from?: string;
}

export interface TableLeftPayload {
  tables: unknown[];
  tableId: string;
  reason?: string;
}

export interface ReconstructSubmitPayload {
  table_id: string;
  pk_hex: string;
  /** 新协议 reconstruction statement（服务端逐字段校验绑定）。 */
  statement: unknown;
  proof: unknown;
}

export interface HandRevealReturn {
  failedCards: unknown[];
  playerPk: string;
  failedCardIndices?: number[];
}

export interface ReconstructResult {
  statement: unknown;
  proof: unknown;
}

export interface JoinAndShuffleResult {
  mask_and_shuffle_round: {
    mask_cards: unknown;
    output_cards: unknown;
    remask_proof: unknown;
    shuffle_proof: unknown;
  };
  pk_ownership_proof: unknown;
}

export function wrapCryptoOp<T>(op: () => T, name: string): T {
  try {
    return op();
  } catch (e) {
    logger.error(`[Crypto] ${name} failed:`, e);
    throw e;
  }
}

/**
 * Parse a WASM result that may be returned as a JSON string or as an
 * already-deserialized object. Centralizes the
 * `typeof result === 'string' ? JSON.parse(result) : result` pattern.
 */
export function parseWasmResult<T>(result: string | T): T {
  return typeof result === 'string' ? JSON.parse(result) : result;
}
