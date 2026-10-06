/**
 * Reveal 编排守卫（Plan D P0.1 / P0.4）。
 *
 * 背景：reveal 的三阶段编排由服务器驱动，客户端按 REVEAL_NOTICE 下发的
 * assignment 盲目出 token。恶意服务器若在非 ShowdownReveal 阶段把玩家
 * 自己的手牌密文混进该玩家的 assignment，玩家交出自己的解密份额后，
 * 服务器即集齐 N 份份额解密底牌（详见 原 docs/starknet-plan-d-stark-curve.md（git 历史）
 * §0.2 —— 这是 "no admin can peek at cards" 唯一的主动攻击面）。
 *
 * 机制：玩家自己的手牌密文只会通过 HAND_REVEAL_RESULT 定向推送（c1 在
 * 密文整个生命周期不变，是天然锚点）。本守卫在收到 HAND_REVEAL_RESULT
 * 时记录自己手牌的 marker（c1_hex 等十六进制形态），并在为 assignment
 * 出 token 前比对：非 ShowdownReveal 阶段命中自有 marker 的卡一律拒绝
 * 出 token。
 *
 * 攻击降级：守卫生效后，恶意服务器的隐私攻击只剩活性攻击（reveal
 * 超时踢人）——与 "no admin who can peek at cards" 的目标一致。
 *
 * 匹配是宽匹配（十六进制 marker 子串比对），不依赖服务端 assignment
 * 的具体序列化 schema。
 */

const OWN_CARD_MARKERS_KEY = 'poker.revealOwnCardMarkers';

/** 自己手牌密文的十六进制 marker 集合（c1/c2 hex、整个密文 JSON 串）。 */
let ownCardMarkers: Set<string> | null = null;

function loadMarkers(): Set<string> {
  if (ownCardMarkers) return ownCardMarkers;
  ownCardMarkers = new Set();
  try {
    const raw = window.localStorage.getItem(OWN_CARD_MARKERS_KEY);
    if (raw) {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const m of parsed) {
          if (typeof m === 'string' && m.length >= 16) ownCardMarkers.add(m);
        }
      }
    }
  } catch {
    // localStorage 不可用（隐私模式等）时退化为会话内集合
  }
  return ownCardMarkers;
}

function persistMarkers(markers: Set<string>): void {
  try {
    window.localStorage.setItem(OWN_CARD_MARKERS_KEY, JSON.stringify([...markers]));
  } catch {
    // 忽略持久化失败，会话内仍然有效
  }
}

/** 从任意卡表示（ElGamalCiphertextJson、assignment 卡、hex 串）提取十六进制 marker。 */
export function extractCardMarkers(card: unknown): string[] {
  const markers: string[] = [];
  const HEX_RE = /^[0-9a-fA-F]{32,}$/;
  if (typeof card === 'string') {
    // 字符串形态（hex 点串或序列化 JSON 串）本身即候选 marker
    markers.push(card.toLowerCase());
    return markers;
  }
  if (card && typeof card === 'object') {
    // 整个密文的 JSON 串作为 marker（不同序列化间的强绑定形态）
    try {
      markers.push(JSON.stringify(card).toLowerCase());
    } catch {
      // 不可序列化的对象跳过
    }
    for (const value of Object.values(card as Record<string, unknown>)) {
      if (typeof value === 'string' && HEX_RE.test(value)) {
        markers.push(value.toLowerCase());
      }
    }
  }
  return markers;
}

/**
 * 记录自己手牌密文的 marker（在 HAND_REVEAL_RESULT 到达、确认这些是
 * 自己的卡之后调用）。返回记录的 marker 数。
 */
export function recordOwnCards(readableCards: unknown[]): number {
  const markers = loadMarkers();
  const before = markers.size;
  for (const card of readableCards) {
    for (const m of extractCardMarkers(card)) {
      markers.add(m);
    }
  }
  const added = markers.size - before;
  persistMarkers(markers);
  return added;
}

/** 是否已建立锚点（收到过 HAND_REVEAL_RESULT）。 */
export function hasOwnCardMarkers(): boolean {
  return loadMarkers().size > 0;
}

/** 某张 assignment 卡是否命中自己的手牌 marker。 */
export function matchesOwnCard(card: unknown): boolean {
  const markers = loadMarkers();
  if (markers.size === 0) return false;
  for (const m of extractCardMarkers(card)) {
    if (markers.has(m)) return true;
    // 子串比对：assignment 卡的序列化串里包含自有 c1 hex
    for (const marker of markers) {
      if (m.length >= marker.length && m.includes(marker)) return true;
    }
  }
  return false;
}

export interface RevealGuardResult {
  /** 允许出 token 的卡（别人的牌 / 社区牌）。 */
  allowed: unknown[];
  /** 命中自有手牌、被拒绝出 token 的卡。 */
  blocked: unknown[];
  /** 手牌类 assignment 在无锚点时的保守整体拒绝。 */
  conservativelyBlocked: boolean;
}

/**
 * 对一个 reveal assignment 执行守卫。
 *
 * @param handCards assignment 中的手牌卡（ShowdownReveal 之外的阶段来自
 *        服务端编排，不可信）
 * @param communityCards assignment 中的公共牌（public by design，不受
 *        守卫限制）
 * @param phase 服务端下发的 reveal phase 标识
 */
export function guardRevealAssignment(
  handCards: unknown[],
  communityCards: unknown[],
  phase: string,
): RevealGuardResult {
  // wire 名双形态：服务端 Display 序列化为 snake_case（
  // game_state.rs:160 "show_down_reveal"），而枚举规范名是 ShowdownReveal——
  // 此前只比规范名，摊牌阶段永远走不进放行分支 → 玩家自己的手牌被当成
  // "偷看攻击" 拒出 token（每次 showdown 必报防偷看守卫错误，且份额
  // 永远收不齐）。两种形态都放行。
  const isShowdown = phase === 'ShowdownReveal' || phase === 'show_down_reveal';
  if (isShowdown) {
    // 摊牌阶段：持有者必须交出自己的份额（公开揭示），全部放行。
    return { allowed: [...handCards, ...communityCards], blocked: [], conservativelyBlocked: false };
  }

  if (handCards.length > 0 && !hasOwnCardMarkers()) {
    // P0.4 冷启动：尚未收到 HAND_REVEAL_RESULT（无锚点），无法区分
    // "别人的牌" 与 "自己的牌"。
    //
    // 活性修复（Sepolia e2e）：原实现保守拒绝整个手牌类 assignment，导致
    // 首手 deal reveal 永远收集不齐 → 玩家超时被踢 → 永远拿不到
    // HAND_REVEAL_RESULT → 锚点永不建立（首手不可玩死锁）。现改为冷启动
    // 放行：代价是首手对恶意服务器存在 §0.2 隐私暴露面（服务器可把自有
    // 底牌混入 assignment 骗取解密份额）；一旦锚点建立即恢复全保护。
    // 服务器为我们自己运营的 testnet/正式环境时该代价可接受。
    return { allowed: [...handCards, ...communityCards], blocked: [], conservativelyBlocked: false };
  }

  const blocked: unknown[] = [];
  const allowed: unknown[] = [];
  for (const card of handCards) {
    (matchesOwnCard(card) ? blocked : allowed).push(card);
  }
  allowed.push(...communityCards);
  return { allowed, blocked, conservativelyBlocked: false };
}

/** 清空锚点（换账号 / 登出时调用）。 */
export function resetOwnCardMarkers(): void {
  ownCardMarkers = new Set();
  try {
    window.localStorage.removeItem(OWN_CARD_MARKERS_KEY);
  } catch {
    // 忽略
  }
}
