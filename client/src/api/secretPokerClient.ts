import httpClient from '../helpers/httpClient';
import type { AxiosError, AxiosRequestConfig } from 'axios';

export interface GameConfig {
  num_players: number;
  cards_per_player: number;
  community_cards: number;
  small_blind: number;
  big_blind: number;
  starting_chips: number;
}

export interface PlayerPublicInfo {
  id: string;
  name: string;
  player_pk: string;
  chips: number;
  current_bet: number;
  folded: boolean;
  card_count: number;
  cards?: (string | null)[];
}

export interface ShuffleState {
  is_active: boolean;
  current_player_pk: string | null;
  completed_players: string[];
  pending_players: string[];
  shuffle_round: number;
  deck_encrypted: ElGamalCiphertextJson[];
}

export interface RevealTokenState {
  is_active: boolean;
  phase: string;
  current_card_index: number;
  total_cards_per_player: number;
  total_community_cards: number;
  completed_players: string[];
  pending_players: string[];
  player_assignments: Record<string, PlayerRevealAssignment>;
}

export interface PlayerRevealAssignment {
  hand_cards: CardEncryptedInfo[];
  community_cards: CardEncryptedInfo[];
}

export interface CardEncryptedInfo {
  card_index: number;
  encrypted_card: ElGamalCiphertextJson;
}

export interface RevealTokenProofJson {
  commitment_t1_hex: string;
  commitment_t2_hex: string;
  response_s_hex: string;
}

export interface SubmitRevealToken {
  card_index: number;
  encrypted_card: ElGamalCiphertextJson;
  reveal_token_proof: RevealTokenProofJson;
  reveal_token_hex: string;
}

export interface SubmitRevealTokenRequest {
  pk_hex: string;
  reveal_tokens: SubmitRevealToken[];
}

export interface GameState {
  game_id: string;
  config: GameConfig;
  phase: string;
  players: PlayerPublicInfo[];
  pot: number;
  current_player_index: number | null;
  community_cards_revealed: number;
  community_cards?: (string | null)[];
  deck_size: number;
  winner: string | null;
  shuffle_state?: ShuffleState | null;
  reveal_token_state?: RevealTokenState | null;
  aggregate_pk?: string;
}

export interface PlayerKeys {
  player_pk: string;
  sk: string;
  pk: string;
}

export interface PKOwnershipProofJson {
  commitment_hex: string;
  response_hex: string;
}

export interface ElGamalCiphertextJson {
  c1_hex: string;
  c2_hex: string;
  c3_hex: string;
}

// ============ 洗牌证明 TS 镜像（服务端 game_state.rs untagged V1/V2）============
// 旧 zk_consistency/triple_dleq 孤儿类型已删除（与两侧实现都对不上，
// 见 design/table/data-gaps-onchain.md D1）：以服务端结构为准。

export interface GeneralizedSchnorrProofJson {
  commitment_hex: string;
  responses_hex: string[];
}

/** V1（Legacy）：生产验证器 fail-closed，仅老回放仍可能出现 */
export interface LegacyShuffleProofJson {
  sum_c1_commit_hex: string;
  sum_c2_commit_hex: string;
  combined_schnorr_proof: GeneralizedSchnorrProofJson;
  sum_c1_schnorr_proof: GeneralizedSchnorrProofJson;
  sum_c2_schnorr_proof: GeneralizedSchnorrProofJson;
  nonce_hex: string;
}

export interface MultiExponentiationArgumentJson {
  c_alpha_hex: string;
  c_beta_hex: string;
  ciphertext_0: ElGamalCiphertextJson;
  ciphertext_1: ElGamalCiphertextJson;
  alpha_response_hex: string[];
  commitment_response_hex: string;
  beta_hex: string;
  beta_blinding_response_hex: string;
  rerandomization_response_hex: string;
}

export interface ProductArgumentJson {
  c_d_hex: string;
  c_delta_hex: string;
  c_capital_delta_hex: string;
  a_response_hex: string[];
  b_response_hex: string[];
  r_response_hex: string;
  s_response_hex: string;
}

export interface BayerGrothShuffleProofJson {
  c_permutation_hex: string;
  c_permuted_powers_hex: string;
  multi_exponentiation: MultiExponentiationArgumentJson;
  product: ProductArgumentJson;
}

/** 服务端 serde(untagged)：V2 显式信封（含 version=2）或历史 V1 形状 */
export type ShuffleProofJson =
  | { version: 2; proof: BayerGrothShuffleProofJson }
  | LegacyShuffleProofJson;

/** untagged 判别：V2 信封带 version 字段 */
export function isV2Proof(p: ShuffleProofJson): p is { version: 2; proof: BayerGrothShuffleProofJson } {
  return (p as { version?: number }).version === 2;
}

export interface RemaskProofJson {
  a_hex: string;
  b_hex: string;
  sum_c1_hex: string;
  sum_d2_hex: string;
  s_hex: string;
  nonce_hex: string;
}

export interface LeaveProofJson {
  per_card_commitments_hex: string[];
  commitment_pk_hex: string;
  response_hex: string;
  nonce_hex: string;
}

export interface LeaveGameRoundJson {
  input_cards: ElGamalCiphertextJson[];
  output_cards: ElGamalCiphertextJson[];
  leave_proof: LeaveProofJson;
}

export interface MaskAndShuffleRoundJson {
  player_pk: string;
  mask_cards: ElGamalCiphertextJson[];
  remask_proof: RemaskProofJson;
  output_cards: ElGamalCiphertextJson[];
  shuffle_proof: ShuffleProofJson;
}

export interface ShuffleRoundJson {
  player_pk: string;
  shuffle_round: number;
  output_cards: ElGamalCiphertextJson[];
  proof: ShuffleProofJson;
}

export interface KeypairResponse {
  sk_hex: string;
  pk_hex: string;
  pk_proof: PKOwnershipProofJson;
}

class ApiClient {
  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    try {
      const config: AxiosRequestConfig = {
        method: (options?.method || 'GET') as AxiosRequestConfig['method'],
        url: path,
        data: options?.body,
        headers: options?.headers as Record<string, string> | undefined,
      };
      const res = await httpClient(config);
      return res.data;
    } catch (err) {
      const axiosErr = err as AxiosError<{ error?: string }>;
      const errorData = axiosErr.response?.data;
      throw new Error(errorData?.error || `HTTP ${axiosErr.response?.status ?? 'unknown'}`);
    }
  }

  async getConfig(): Promise<GameConfig> {
    return this.request<GameConfig>('/config');
  }

  async createGame(config?: Partial<GameConfig>): Promise<{ game_id: string; config: GameConfig }> {
    return this.request('/games', {
      method: 'POST',
      body: JSON.stringify({ config: config || {} }),
    });
  }

  async listGames(): Promise<GameState[]> {
    return this.request('/games');
  }

  async getGame(gameId: string): Promise<GameState> {
    return this.request(`/games/${gameId}`);
  }

  async deleteGame(gameId: string): Promise<void> {
    return this.request(`/games/${gameId}`, { method: 'DELETE' });
  }

  async joinGame(gameId: string, name: string, pkHex: string, pkProof: PKOwnershipProofJson): Promise<{ player: PlayerKeys & { id: string; name: string; chips: number }; message: string }> {
    return this.request(`/games/${gameId}/join`, {
      method: 'POST',
      body: JSON.stringify({ name, pk_hex: pkHex, pk_proof: pkProof }),
    });
  }

  async joinGameAndShuffle(
    gameId: string,
    name: string,
    pkHex: string,
    pkProof: PKOwnershipProofJson,
    maskAndShuffleRound: MaskAndShuffleRoundJson,
  ): Promise<{ player: { id: string; name: string; chips: number }; message: string }> {
    return this.request(`/games/${gameId}/join-game-and-shuffle`, {
      method: 'POST',
      body: JSON.stringify({
        name,
        pk_hex: pkHex,
        pk_proof: pkProof,
        mask_and_shuffle_round: maskAndShuffleRound,
      }),
    });
  }

  async startShuffle(gameId: string): Promise<{ message: string; phase: string }> {
    return this.request(`/games/${gameId}/start`, { method: 'POST' });
  }

  async submitShuffle(gameId: string, shuffleRound: ShuffleRoundJson): Promise<{ message: string; shuffles_received: number; total_players: number }> {
    return this.request(`/games/${gameId}/shuffle`, {
      method: 'POST',
      body: JSON.stringify({ shuffle_round: shuffleRound }),
    });
  }

  async dealCards(gameId: string): Promise<{ message: string; phase: string; players_dealt: number }> {
    return this.request(`/games/${gameId}/deal`, { method: 'POST' });
  }

  async revealCard(gameId: string, playerPk: string, cardIndex: number): Promise<{ message: string }> {
    return this.request(`/games/${gameId}/reveal/card`, {
      method: 'POST',
      body: JSON.stringify({ player_pk: playerPk, card_index: cardIndex }),
    });
  }

  async revealCommunityCard(gameId: string): Promise<{ message: string; revealed: number; total: number }> {
    return this.request(`/games/${gameId}/reveal/community`, { method: 'POST' });
  }

  async showdown(gameId: string): Promise<{ message: string; winner: string | null; is_finished: boolean; phase: string }> {
    return this.request(`/games/${gameId}/showdown`, { method: 'POST' });
  }

  async performAction(
    gameId: string,
    playerPk: string,
    action: 'fold' | 'call' | 'raise' | 'check' | 'all_in',
    amount?: number
  ): Promise<GameState> {
    return this.request(`/games/${gameId}/action`, {
      method: 'POST',
      body: JSON.stringify({ player_pk: playerPk, action, amount }),
    });
  }

  async nextRound(gameId: string): Promise<{ message: string; community_revealed: number; pot: number }> {
    return this.request(`/games/${gameId}/next-round`, { method: 'POST' });
  }

  async submitRevealToken(gameId: string, req: SubmitRevealTokenRequest): Promise<{ message: string; player_pk: string; results: Array<{ card_index: number; status?: string; error?: string }>; phase: string; reveal_phase_complete: boolean }> {
    return this.request(`/games/${gameId}/reveal-token`, {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  /** 牌局记录看板：最近手牌列表（新→旧，服务器每桌保留 ≤100 条） */
  async getHandHistory(tableId: number | string): Promise<HandHistoryRecord[]> {
    return this.request(`/tables/${tableId}/history`);
  }

  /** 牌局记录看板：单手详情 */
  async getHandRecord(tableId: number | string, handSeq: number): Promise<HandHistoryRecord> {
    return this.request(`/tables/${tableId}/history/${handSeq}`);
  }

  /**
   * D1 洗牌证明通道：按手查每层证明本体 + verified/tx + V1 布局投影。
   * `handId` 缺省按 hand_seq 映射；传 ClientTable.handId 可查进行中的手
   * （还没进 history）。
   */
  async getHandProof(
    tableId: number | string,
    handSeq: number,
    handId?: number,
  ): Promise<HandProofResponse> {
    const suffix = handId && handId > 0 ? `?handId=${handId}` : '';
    return this.request(`/tables/${tableId}/hands/${handSeq}/proof${suffix}`);
  }
}

/** D1 证明通道：单层洗牌证明留存（服务端 ShuffleLayerRecord，camelCase） */
export interface ShuffleLayerRecord {
  /** 手内轮次（含开局洗牌与 reconstruct 重加密轮） */
  round: number;
  seat: number;
  playerPk: string;
  playerName: string;
  /** 1 = LegacyV1，2 = Bayer-Groth V2 */
  proofVersion: number;
  proof: ShuffleProofJson;
  /** V1 布局展示投影（方案 b：V2 行为派生摘要时 derived=true） */
  display: {
    sumC1Commit: string | null;
    sumC2Commit: string | null;
    combinedSchnorrProof: string | null;
    sumC1SchnorrProof: string | null;
    sumC2SchnorrProof: string | null;
    nonce: string | null;
    derived: boolean;
  };
  /** V2：验证后 transcript squeeze 的全局挑战；V1 无 */
  globalChallenge?: string;
  verified: boolean;
  txDigest?: string | null;
  ts: number;
}

/** D4 结算回执（服务端 HandSettleReceipt，camelCase） */
export interface HandSettleReceipt {
  tableId: number;
  handId: number;
  handSeq?: number;
  status: 'settled' | 'refused' | 'failed';
  exit: 'appchain' | 'dual' | 'legacy';
  handBinding?: string;
  aggregateDigest?: string;
  txDigests: string[];
  blockNumber?: number;
  gasFee?: string;
  contract?: string;
  verifier?: string;
  settleOpIndex?: number;
  batchRoot?: string;
  proven?: boolean;
  reason?: string;
  tsMs: number;
}

/** D3 链上元数据（服务端 ChainMeta，camelCase） */
export interface ChainMeta {
  exit: string;
  contract: string | null;
  dualSettlement: string | null;
  settlement: string | null;
  vault: string | null;
  verifier: string | null;
  gateway: string | null;
}

/** D1 证明通道响应 */
export interface HandProofResponse {
  tableId: number;
  handSeq: number;
  handId: number;
  aggregatePk: string | null;
  deckSize: number;
  layers: ShuffleLayerRecord[];
  settlement: HandSettleReceipt | null;
  chain: ChainMeta;
}

/** 单手牌终局记录（服务器 HandHistoryRecord，camelCase） */
export interface HandHistoryRecord {
  handSeq: number;
  handOverAt: number;
  wentToShowdown: boolean;
  grossPot: number;
  rakeCollected: number;
  sidePots: { amount: number; players?: number[] }[];
  board: { suit: string; rank: string }[];
  /** 已亮出的玩家手牌（seat → 两张底牌；仅摊牌亮牌座位） */
  holeCards: Record<string, { suit: string; rank: string }[]>;
  winMessages: string[];
  seats: Record<string, {
    player: { id: string | null; username: string | null };
    bet: number;
    stack: number;
  }>;
  streets: unknown[];
  /** 开局时间（epoch ms；服务端 hand_started_at，用于「用时」） */
  handStartedAt?: number;
  /** 摊牌各家牌型（服务端 Vec<ShowdownHandRank>；fold-win 手为空） */
  showdownHandRanks?: Array<{ seat: number; rank: string }>;
  /** 每家净结果（[seat, net] 元组数组，正 = 赢） */
  nets?: Array<[number, number]>;
  /** 逐动作流水（服务端 actions：seat/player/action/amount/street/ts/auto） */
  actions?: Array<{
    seat: number;
    player?: string | null;
    action: string;
    amount: number;
    street?: string;
    ts?: number;
    auto?: boolean;
  }>;
  /** 本手 id（证明通道 / 结算回执的映射锚点；0 = 旧记录未记录） */
  handId?: number;
}

export const api = new ApiClient();
export default api;
