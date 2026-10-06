/**
 * 牌桌派生数据：全部由 Table 现有字段推导，不依赖新增服务端字段。
 * 对应设计稿（design/table/zchain-table-ui.html）的 T2/T3 决策信息：
 * 盲注角色标注、底池赔率、跟注占余量、加注四档位。
 */
import { Table } from '../types/game';

export type BlindRole = 'btn' | 'sb' | 'bb';

/**
 * 按 button 推导各座位的盲注角色（BTN 已有独立图标，这里一并返回便于复用）。
 * - 3 人及以上：小盲 = 按钮后第一个在座，大盲 = 再下一个在座；
 * - 2 人（heads-up）：按钮即小盲，对方大盲（标准规则）。
 * button = 0（未开局）时返回空。
 */
export function blindRoles(table: Table): Record<number, BlindRole> {
  const roles: Record<number, BlindRole> = {};
  const button = table.button;
  if (!button) return roles;

  // 座位环大小：客户端固定 5 座布局；若服务端下发更多座位则取最大座位号
  const maxPlayers = Math.max(
    5,
    button,
    ...Object.keys(table.seats).map(Number),
  );
  const occupied = Object.values(table.seats)
    .filter((s) => s && s.player)
    .map((s) => s.id)
    .sort((a, b) => a - b);
  if (occupied.length < 2) {
    if (occupied.length === 1 && table.seats[button]?.player) {
      roles[button] = 'btn';
    }
    return roles;
  }
  roles[button] = 'btn';

  const nextOccupied = (from: number): number => {
    for (let step = 1; step <= maxPlayers; step++) {
      const candidate = ((from - 1 + step) % maxPlayers) + 1;
      if (occupied.includes(candidate)) return candidate;
    }
    return from;
  };

  if (occupied.length === 2) {
    // heads-up：按钮 = 小盲
    const sb = button;
    const bb = occupied.find((id) => id !== button)!;
    roles[sb] = 'sb';
    roles[bb] = 'bb';
  } else {
    const sb = nextOccupied(button);
    const bb = nextOccupied(sb);
    roles[sb] = 'sb';
    roles[bb] = 'bb';
  }
  return roles;
}

/** 待跟差额（自己视角）：callAmount 为本轮总额，seat.bet 为已投入。 */
export function toCallAmount(table: Table, seatId: number): number {
  const seat = table.seats[seatId];
  if (!seat) return 0;
  return Math.max(table.callAmount - seat.bet, 0);
}

/** 底池赔率 (pot + call) : call；无需跟注时返回 null。保留 1 位小数。 */
export function potOdds(table: Table, seatId: number): number | null {
  const toCall = toCallAmount(table, seatId);
  if (toCall <= 0) return null;
  return Math.round(((table.pot + toCall) / toCall) * 10) / 10;
}

/** 金额占余量百分比（如 跟注 555 / 余量 4450 → 12.5）。 */
export function percentOfStack(table: Table, seatId: number, amount: number): number | null {
  const seat = table.seats[seatId];
  if (!seat || seat.stack <= 0 || amount <= 0) return null;
  return Math.round((amount / seat.stack) * 1000) / 10;
}

export interface RaisePresets {
  /** 最小加注到的总额（= minRaise） */
  min: number;
  /** 半池加注到的总额 */
  halfPot: number;
  /** 底池加注到的总额 */
  pot: number;
  /** 全下总额（stack + 本轮已投入） */
  allIn: number;
}

/**
 * 加注四档位（最小 / 半池 / 底池 / 全下），全部为「加注到」的 street 总额，
 * 与 GameUI 的 raise(amount= bet + seat.bet) 同口径。
 * 档位对齐 BetSlider 的 step=10，并 clamp 到 [min, allIn]。
 */
export function raisePresets(table: Table, seatId: number): RaisePresets | null {
  const seat = table.seats[seatId];
  if (!seat) return null;

  const allIn = seat.stack + seat.bet;
  const min = Math.min(Math.max(table.minRaise, 0), allIn);
  if (allIn <= 0) return null;

  // 底池加注 = 当前注额 + 跟注后的底池（标准 no-limit 公式）
  const toCall = toCallAmount(table, seatId);
  const potRaiseTo = table.callAmount + table.pot + toCall;

  const round10 = (n: number) => Math.round(n / 10) * 10;
  const clamp = (n: number) => Math.min(Math.max(round10(n), min), allIn);

  return {
    min,
    halfPot: clamp(min + (potRaiseTo - min) / 2),
    pot: clamp(potRaiseTo),
    allIn,
  };
}
