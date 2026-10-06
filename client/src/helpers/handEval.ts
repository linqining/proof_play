/**
 * 7 选 5 最优牌型评估器（仅本地展示用：自己底牌 + 公共牌的牌型标注，
 * 对应设计稿 T3「三条 A · 顶三条」）。不参与任何判定逻辑——
 * 胜负判定以服务端 evaluate_player_hands 为准。
 */
import { Card } from '../types/game';

export type HandCategory =
  | 'high-card'
  | 'one-pair'
  | 'two-pair'
  | 'three-of-a-kind'
  | 'straight'
  | 'flush'
  | 'full-house'
  | 'four-of-a-kind'
  | 'straight-flush'
  | 'royal-flush';

const RANK_VALUE: Record<string, number> = {
  '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
  '10': 10, J: 11, Q: 12, K: 13, A: 14,
};

export interface HandEvalResult {
  category: HandCategory;
  /** 牌型名对应的 i18n key：game_handrank_<category> */
  i18nKey: string;
  /** 主要牌点（如三条的点数），用于「三条 A」中的 A；高牌时为最大牌 */
  mainRank: number;
}

const rankValue = (r: string): number => RANK_VALUE[r?.toUpperCase?.() ?? r] ?? 0;

const CATEGORY_ORDER: HandCategory[] = [
  'high-card',
  'one-pair',
  'two-pair',
  'three-of-a-kind',
  'straight',
  'flush',
  'full-house',
  'four-of-a-kind',
  'straight-flush',
  'royal-flush',
];

/** 5 张牌评分：[类别, t1..t5] 按 15 进制打包，可直接比较大小。 */
function score5(cards: Card[]): number {
  const values = cards.map((c) => rankValue(c.rank)).sort((a, b) => b - a);
  const suits = new Set(cards.map((c) => c.suit?.toLowerCase()));
  const isFlush = suits.size === 1;

  // 牌点计数分组
  const counts = new Map<number, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  // 按数量降序、点数降序排列 [count, value]
  const groups = [...counts.entries()]
    .map(([v, n]) => [n, v] as [number, number])
    .sort((a, b) => b[0] - a[0] || b[1] - a[1]);

  const isStraight = (() => {
    const uniq = [...new Set(values)].sort((a, b) => b - a);
    if (uniq.length !== 5) return false;
    if (uniq[0] - uniq[4] === 4) return true;
    // A-5-4-3-2（轮子）
    return uniq[0] === 14 && uniq[1] === 5 && uniq[1] - uniq[4] === 3;
  })();
  // 轮子（A 作 1）直子的最高牌按 5 计
  const straightHigh = (() => {
    if (!isStraight) return 0;
    const uniq = [...new Set(values)].sort((a, b) => b - a);
    return uniq[0] === 14 && uniq[1] === 5 ? 5 : uniq[0];
  })();

  // 固定 5 个 tiebreak 槽（不足补 0），保证不同类别的分值位数一致、可比较
  const pack = (cat: number, tiebreak: number[]): number => {
    const tb = [...tiebreak.slice(0, 5)];
    while (tb.length < 5) tb.push(0);
    return tb.reduce((acc, v) => acc * 15 + v, cat);
  };

  if (isStraight && isFlush) {
    return straightHigh === 14 ? pack(9, [14]) : pack(8, [straightHigh]);
  }
  if (groups[0][0] === 4) return pack(7, groups.map((g) => g[1]));
  if (groups[0][0] === 3 && groups[1]?.[0] === 2) return pack(6, groups.map((g) => g[1]));
  if (isFlush) return pack(5, values);
  if (isStraight) return pack(4, [straightHigh]);
  if (groups[0][0] === 3) return pack(3, groups.map((g) => g[1]));
  if (groups[0][0] === 2 && groups[1]?.[0] === 2) return pack(2, groups.map((g) => g[1]));
  if (groups[0][0] === 2) return pack(1, groups.map((g) => g[1]));
  return pack(0, values);
}

/** 解包评分首个字段（类别），并取 tiebreak 首位（主牌点）。 */
function unpack(score: number): { cat: number; main: number } {
  let s = score;
  const digits: number[] = [];
  // pack 产生 6 位 15 进制（cat + 5 tiebreak）
  for (let i = 0; i < 6; i++) {
    digits.unshift(s % 15);
    s = Math.floor(s / 15);
  }
  return { cat: digits[0], main: digits[1] || digits[0] };
}

/** 评估 5–7 张牌的最优 5 张组合。牌数不足 5 或含未知道具返回 null。 */
export function evaluateBestHand(cards: Card[]): HandEvalResult | null {
  const clean = cards.filter((c) => rankValue(c.rank) > 0 && c.suit);
  if (clean.length < 5) return null;

  let best = -1;
  const n = clean.length;

  const combos5 = (arr: Card[]): Card[][] => {
    const out: Card[][] = [];
    const pick = (start: number, cur: Card[]) => {
      if (cur.length === 5) {
        out.push([...cur]);
        return;
      }
      for (let i = start; i < arr.length; i++) pick(i + 1, [...cur, arr[i]]);
    };
    pick(0, []);
    return out;
  };

  for (const combo of combos5(clean)) {
    const s = score5(combo);
    if (s > best) best = s;
  }
  if (best < 0) return null;

  const { cat, main } = unpack(best);
  const category = CATEGORY_ORDER[cat] ?? 'high-card';
  return { category, i18nKey: `game_handrank_${category}`, mainRank: main };
}

/** 主牌点 → 显示名（A/K/Q/J/10…），用于「三条 A」的 A 部分。 */
export function rankLabel(value: number): string {
  const map: Record<number, string> = { 11: 'J', 12: 'Q', 13: 'K', 14: 'A' };
  return map[value] ?? String(value);
}
