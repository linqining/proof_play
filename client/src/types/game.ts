// 游戏相关类型定义

export type RoundStateType =
  | 'waiting'
  | 'shuffling'
  | 'shuffleComplete'
  | 'preFlopReveal'
  | 'preFlop'
  | 'flopReveal'
  | 'flop'
  | 'turnReveal'
  | 'turn'
  | 'riverReveal'
  | 'river'
  | 'showdownReveal'
  | 'showdown'
  | 'handComplete';

export const RoundState = {
  Waiting: 'waiting',
  Shuffling: 'shuffling',
  ShuffleComplete: 'shuffleComplete',
  PreFlopReveal: 'preFlopReveal',
  PreFlop: 'preFlop',
  FlopReveal: 'flopReveal',
  Flop: 'flop',
  TurnReveal: 'turnReveal',
  Turn: 'turn',
  RiverReveal: 'riverReveal',
  River: 'river',
  ShowdownReveal: 'showdownReveal',
  Showdown: 'showdown',
  HandComplete: 'handComplete',
} as const;

export interface Card {
  suit: string;
  rank: string;
}

export interface Player {
  socketId: string;
  pkHex: string;
  name: string;
  chips: number;
  sittingOut: boolean;
}

export interface Seat {
  id: number;
  player: Player | null;
  hand: Card[];
  turn: boolean;
  chips: number;
  bet: number;
  sittingOut: boolean;
  stack: number;
  lastAction: string | null;
  /** 玩家是否已 fold（与后端 ClientSeat.folded 对齐，camelCase 序列化） */
  folded?: boolean;
  /** 等待下一手入局（后端 ClientSeat.isWaiting；中途买入未入局时为 true） */
  isWaiting?: boolean;
  /** 本手累计投入（后端 ClientSeat.totalBet；旧服务端不下发时缺省） */
  totalBet?: number;
}

export interface ShuffleState {
  is_active: boolean;
  current_player_pk: string;
  deck_encrypted: string[][];
  aggregate_pk: string;
  completed_players: string[];
  pending_players: string[];
  /** 本手 id（动作签名域 v2；开局广播分配） */
  hand_id: number;
  /** 当前洗牌者是否需补自身密钥层（waiting 入座玩家）——true 时走 join_game_and_shuffle。 */
  needs_join_layer?: boolean;
  /** 聚合公钥减去当前洗牌者公钥（join_game_and_shuffle 的 curr_share_pk）。 */
  share_pk?: string;
}

export interface RevealTokenState {
  phase?: string;
  pending_players?: string[];
  completed_players?: string[];
  player_assignments: Record<
    string,
    {
      hand_cards?: Array<{ encrypted_card: string }>;
      community_cards?: Array<{ encrypted_card: string }>;
      hand_card?: Array<{ encrypted_card: string }>;
      community_card?: Array<{ encrypted_card: string }>;
    }
  >;
}

/** 服务器快照中的 reconstruct 状态（字段与 RECONSTRUCT_NOTICE 一致，snake_case）。 */
export interface ReconstructState {
  is_active: boolean;
  completed_players: string[];
  pending_players: string[];
  cards: string[];
  aggregate_pk: string;
  context_digest: string;
  reconstruction_epoch: number;
  prior_state_digests?: Record<string, string>;
  player_residual_carriers?: Record<string, {
    residual_carriers: unknown[];
  }>;
}

export interface SidePot {
  amount: number;
  /** 可争该池的座位列表（后端 SidePot.players；旧服务端不下发时缺省） */
  players?: number[];
}

export interface Table {
  id: string;
  /** 桌名（后端 ClientTable.name 已下发；缺省时 UI 回退显示 id） */
  name?: string;
  /** Optional chain-side table id. Not used by the client in the Starknet flow
   * (per-hand poker actions are off-chain through the game server), but kept
   * so downstream code can still reference it when wired up. */
  chainTableId?: string;
  seats: Record<number, Seat>;
  roundState: RoundStateType;
  /** 本手 id（动作签名域 v2）。洗牌结束后 shuffleState 为 null，下注阶段
   * 的动作签名从这里取 hand_id（服务端 ClientTable.hand_id）。 */
  handId?: number;
  shuffleState: ShuffleState | null;
  revealTokenState: RevealTokenState | null;
  reconstructState?: ReconstructState | null;
  deck?: {
    cards: string[][];
  };
  pot: number;
  currentBet: number;
  minBuyIn: number;
  maxBuyIn: number;
  bigBlind: number;
  smallBlind: number;
  dealerSeatId: number;
  limit: number;
  minBet: number;
  minRaise: number;
  button: number;
  callAmount: number;
  handOver: boolean;
  mainPot: number;
  sidePots: SidePot[];
  players: Player[];
  board: Card[];
  wentToShowdown: boolean;
  winMessages: string[];
  /** 本手已收台费（摊牌结算时按链上口径收取，0 = 未抽水） */
  rakeCollected: number;
  /** 台费费率（万分比，后端 RakeParams.rake_bps；缺省不显示费率） */
  rakeBps?: number;
  /** 台费单手上限（后端 RakeParams.rake_cap；缺省不显示上限） */
  rakeCap?: number;
  /** 当前回合计时起点（epoch ms，后端 betting_started_at；随每次行动重置） */
  bettingStartedAt?: number;
  /** 回合超时总时长（ms，后端 config.betting_timeout_secs；缺省客户端回退 15s） */
  bettingTimeoutMs?: number;
  /** 上一手终局时间（epoch ms，后端 hand_complete_at；用于"下一手"倒计时） */
  handCompleteAt?: number;
  /** 终局到下一手开局的等待时长（ms，后端 hand_complete_wait_secs） */
  handCompleteWaitMs?: number;
  /** 摊牌各家牌型（仅摊牌手有值；服务端 Vec<ShowdownHandRank>） */
  showdownHandRanks?: Array<{ seat: number; rank: string }>;
  /** 桌台已关闭（终态）：服务端不再开局、不再接受入座。 */
  closed?: boolean;
}

export interface GameMessage {
  text: string;
  timestamp: number;
}

export interface GameContextType {
  messages: GameMessage[];
  currentTable: Table | null;
  isPlayerSeated: boolean;
  seatId: number | null;
  shuffleLoading: boolean;
  revealLoading: boolean;
  decryptedHandCards: string[];
  communityCards: Card[];
  kickNotification: string | null;
  cryptoEvents: CryptoEvent[];
  /** D4 结算终局回执（handId → 最新回执；`settlement_result` WS 事件维护） */
  settlementReceipts: Record<number, SettlementReceipt>;
  leaveDeferred: boolean;
  setLeaveDeferred: (value: boolean) => void;
  /** 当玩家在手牌进行中且未 fold 时点击离开，置为 true 以触发确认弹窗（Task 7 渲染弹窗） */
  showFoldLeaveConfirm: boolean;
  /** 用户确认 fold 并离开：调用 fold() 后进入 deferred leave 流程 */
  confirmFoldLeave: (shouldNavigate?: boolean, pkHex?: string) => void;
  /** 用户取消 fold 并离开 */
  cancelFoldLeave: () => void;
  /** 用户在 deferred banner 上取消离开：中断进行中的 performDeferredLeave */
  cancelDeferredLeave: () => void;
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
  standUp: () => Promise<void>;
  addMessage: (message: string) => void;
  fold: () => void;
  check: () => void;
  call: () => void;
  raise: (amount: number) => void;
  rebuy: (tableId: string, seatId: number, amount: number) => void;
  sittingOut: () => void;
  sittingIn: () => void;
  expelInitiate: (tableId: string, targetPlayerPk: string) => void;
  clearKickNotification: () => void;
  isActionLoading: boolean;
  startActionLoading: () => void;
}

// ===== ZK 密码学事件（用于可视化面板） =====
export type CryptoEventType = 'shuffle' | 'remask' | 'reveal_token' | 'leave' | 'reconstruct';

export interface CryptoEvent {
  type: 'crypto_event';
  event_type: CryptoEventType;
  player_pk: string;
  card_index: number | null;
  tx_digest: string | null;
  verified: boolean;
  timestamp: number;
  message?: string;
}

/** D4 结算终局回执（服务端 HandSettleReceipt 镜像，camelCase） */
export interface SettlementReceipt {
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
