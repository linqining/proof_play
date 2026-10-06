/**
 * 自己手牌密文的 c1 锚点缓存（离开/弃牌剥层排除集的客户端来源）。
 *
 * 背景（离开不亮牌 bug）：leave/fold 剥层输出公开即公开 sk·c1（= 自己
 * 对每张牌的 reveal token）。构建离开证明时必须排除自己手牌的牌组槽位。
 * 客户端侧的槽位来源 = HAND_REVEAL_RESULT 推送的手牌密文（c1 在整个
 * reveal 生命周期不变，可与牌组密文 c1 匹配定位槽位）。
 *
 * 服务端从发牌状态推导同一集合并强校验（排除槽必须原样保留）——缓存
 * 缺失时客户端交不出正确排除集会被服务端拒绝（fail-closed），不会静默
 * 退回"全牌剥层"的不安全形态。
 */

const OWN_HOLE_C1_KEY = 'poker.ownHoleC1';

let ownHoleC1: Set<string> | null = null;

function load(): Set<string> {
  if (ownHoleC1) return ownHoleC1;
  ownHoleC1 = new Set();
  try {
    const raw = window.localStorage.getItem(OWN_HOLE_C1_KEY);
    if (raw) {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const m of parsed) {
          if (typeof m === 'string' && m.length >= 16) ownHoleC1.add(m);
        }
      }
    }
  } catch {
    // localStorage 不可用时退化为会话内集合
  }
  return ownHoleC1;
}

function persist(markers: Set<string>): void {
  try {
    window.localStorage.setItem(OWN_HOLE_C1_KEY, JSON.stringify([...markers]));
  } catch {
    // 忽略持久化失败
  }
}

/** 从密文线格式提取 c1（hex 字符串数组或对象）。 */
export function extractC1(card: unknown): string {
  if (Array.isArray(card)) return String(card[0] ?? '');
  if (card && typeof card === 'object') {
    const o = card as { c1_hex?: string; c1?: string };
    return o.c1_hex || o.c1 || '';
  }
  return '';
}

/** HAND_REVEAL_RESULT 到达时记录自己手牌密文的 c1。 */
export function recordOwnHoleCiphertexts(readableCards: unknown[]): void {
  const markers = load();
  for (const card of readableCards) {
    const c1 = extractC1(card);
    if (c1) markers.add(c1);
  }
  persist(markers);
}

/** 当前手牌的 c1 集合（匹配牌组密文定位槽位）。 */
export function ownHoleC1Set(): Set<string> {
  return load();
}

/** 换手/登出清空。 */
export function resetOwnHoleCards(): void {
  ownHoleC1 = new Set();
  try {
    window.localStorage.removeItem(OWN_HOLE_C1_KEY);
  } catch {
    // 忽略
  }
}
