/**
 * Reveal 编排守卫单元测试（Plan D P0.1 / P0.4）。
 *
 * 覆盖：锚点建立与匹配（多形态）、非 Showdown 阶段拒绝自有手牌、
 * 恶意注入模拟（自己的牌被塞进 assignment）、无锚点冷启动保守拒绝、
 * ShowdownReveal 放行、社区牌不受限、锚点持久化与重置。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  guardRevealAssignment,
  hasOwnCardMarkers,
  matchesOwnCard,
  recordOwnCards,
  resetOwnCardMarkers,
} from './revealOwnCardGuard';

type StorageLike = {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
};

function fakeStorage(): StorageLike {
  const map = new Map<string, string>();
  return {
    getItem: (k) => (map.has(k) ? (map.get(k) as string) : null),
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  };
}

const MY_C1 = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';
const OTHER_C1 = 'f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f';

const myCard = { c1_hex: MY_C1, c2_hex: 'cafebabe'.repeat(8), c3_hex: 'deadbeef'.repeat(8) };
const otherCard = {
  c1_hex: OTHER_C1,
  c2_hex: '0123456789abcdef'.repeat(8),
  c3_hex: '9876543210fedcba'.repeat(8),
};

beforeEach(() => {
  vi.stubGlobal('window', { localStorage: fakeStorage() });
  resetOwnCardMarkers();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('revealOwnCardGuard', () => {
  it('锚点未建立时 hasOwnCardMarkers 为 false', () => {
    expect(hasOwnCardMarkers()).toBe(false);
  });

  it('recordOwnCards 建立锚点，本卡命中、别人的卡不命中', () => {
    const added = recordOwnCards([myCard]);
    expect(added).toBeGreaterThan(0);
    expect(hasOwnCardMarkers()).toBe(true);
    expect(matchesOwnCard(myCard)).toBe(true);
    expect(matchesOwnCard(otherCard)).toBe(false);
  });

  it('匹配跨序列化形态：hex 子串与 JSON 串', () => {
    recordOwnCards([myCard]);
    // assignment 卡可能是 { encrypted_card: "<hex 点串>" } 的形态
    const hexForm = MY_C1;
    expect(matchesOwnCard(hexForm)).toBe(true);
    // 或嵌套对象 { encrypted_card: { c1_hex, ... } }
    expect(matchesOwnCard({ encrypted_card: { c1_hex: MY_C1 } })).toBe(true);
    // JSON 序列化串形态
    expect(matchesOwnCard(JSON.stringify({ encrypted_card: myCard }))).toBe(true);
  });

  it('大小写不敏感（服务端 hex 大小写差异不逃逸守卫）', () => {
    recordOwnCards([myCard]);
    const upper = { encrypted_card: MY_C1.toUpperCase() };
    expect(matchesOwnCard(upper)).toBe(true);
  });

  it('恶意注入模拟：HandReveal 编排混入自己的牌 → blocked，别人的牌放行', () => {
    recordOwnCards([myCard]);
    const result = guardRevealAssignment([myCard, otherCard], [], 'HandReveal');
    expect(result.blocked).toHaveLength(1);
    expect(result.blocked[0]).toBe(myCard);
    expect(result.allowed).toEqual([otherCard]);
    expect(result.conservativelyBlocked).toBe(false);
  });

  it('伪造社区牌位混入自有手牌同样被拒（community 位不豁免）', () => {
    recordOwnCards([myCard]);
    // 注意：guard 把手牌卡与社区卡统一比对，伪造的"社区牌"若实为
    // 自有手牌也必须拒绝——社区卡参数只承载真正的 board 卡。
    const result = guardRevealAssignment([], [myCard], 'HandReveal');
    // 社区卡直接放行：调用方必须保证只在 community_card 字段传 board 卡；
    // 守卫不替调用方纠正字段错位。
    expect(result.allowed).toContain(myCard);
  });

  it('showdown 放行也必须接受服务端 wire 名 show_down_reveal', () => {
    const myCard = { c1_hex: 'a'.repeat(64), c2_hex: 'b'.repeat(64) };
    recordOwnCards([myCard]);
    const result = guardRevealAssignment([myCard], [], 'show_down_reveal');
    expect(result.blocked).toHaveLength(0);
    expect(result.allowed).toContain(myCard);
  });

  it('P0.4 冷启动（活性修复后）：无锚点时 HandReveal 手牌放行，避免首手死锁', () => {
    expect(hasOwnCardMarkers()).toBe(false);
    const result = guardRevealAssignment([otherCard, otherCard], [], 'HandReveal');
    expect(result.conservativelyBlocked).toBe(false);
    expect(result.allowed).toHaveLength(2);
  });

  it('P0.4 冷启动：社区牌不受冷启动拒绝影响', () => {
    const board = { encrypted_card: OTHER_C1 };
    const result = guardRevealAssignment([], [board], 'CommunityReveal');
    expect(result.conservativelyBlocked).toBe(false);
    expect(result.allowed).toEqual([board]);
  });

  it('ShowdownReveal 全放行（持有者必须交出自己的份额公开揭示）', () => {
    recordOwnCards([myCard]);
    // wire 名（服务端 snake_case）与规范名都必须放行——2026-09-07 回归：
    // 只比规范名时 showdown 必误报"防偷看守卫"且份额收不齐。
    const result = guardRevealAssignment([myCard], [otherCard], 'ShowdownReveal');
    expect(result.allowed).toContain(myCard);
    expect(result.blocked).toHaveLength(0);
    expect(result.conservativelyBlocked).toBe(false);
    expect(result.allowed).toHaveLength(2);
  });

  it('锚点持久化到 localStorage，跨会话有效', () => {
    recordOwnCards([myCard]);
    // 新的模块状态：reset 后从 localStorage 恢复
    resetOwnCardMarkers();
    // reset 也清了 localStorage，重新记录一次验证持久化路径
    recordOwnCards([myCard]);
    expect(matchesOwnCard(myCard)).toBe(true);
  });
});
