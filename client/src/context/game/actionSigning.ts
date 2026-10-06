/**
 * #16 抗审查动作签名（客户端侧）。
 *
 * 以牌局身份 SK（PlayerContext 的 skHex，Stark curve）对动作
 * (tableId, handId, seq, action, amount) 做 wasm 签名；seq 按桌持久化在
 * localStorage（`poker.actionSeq:{tableId}`），保证服务端看到的
 * 每座位 seq 严格单调。
 *
 * 签名域与 texas/src/starknet/game_action…（poker_protocol
 * `game_action::action_msg_bytes`）逐字节一致；wasm 能力缺失或旧 pkg
 * （无 sign_action 导出）时返回 null，动作以未签名形态发出
 * （迁移期兼容，服务端按 enforcement 开关决定是否拒绝）。
 */

interface ActionSigResult {
  r_hex: string;
  s_hex: string;
}

let wasmSign: ((sk: string, tableId: number, handId: number, seq: bigint, action: string, amount: bigint) => ActionSigResult) | null = null;
let wasmProbed = false;

async function loadWasmSign(): Promise<typeof wasmSign> {
  if (wasmProbed) return wasmSign;
  wasmProbed = true;
  try {
    const wasm = (await import('@linqining/client-wasm')) as unknown as Record<string, unknown>;
    const fn = wasm.sign_action;
    if (typeof fn !== 'function') {
      return null; // pkg 构建早于 #16：无动作签名导出
    }
    wasmSign = (sk: string, tableId: number, handId: number, seq: bigint, action: string, amount: bigint) =>
      fn(sk, tableId, handId, seq, action, amount) as ActionSigResult;
  } catch {
    wasmSign = null;
  }
  return wasmSign;
}

function nextSeq(tableId: number | string): number {
  const key = `poker.actionSeq:${tableId}`;
  const current = Number(localStorage.getItem(key) ?? '0') || 0;
  const next = current + 1;
  localStorage.setItem(key, String(next));
  return next;
}

/**
 * 从服务端动作回执 ratchet 本地 seq：服务端 auto 代打会自增 seq
 * （accepted = max(client_seq, server_accepted)），客户端 localStorage
 * 不跟进就会越落越后——签名有效也过不了 seq 单调性
 * （2026-09-08 线上：sig_ok=true seq_ok=false, 101 < 104）。
 */
export function observeServerSeq(tableId: number | string, serverSeq: number) {
  if (!Number.isFinite(serverSeq) || serverSeq <= 0) return;
  const key = `poker.actionSeq:${tableId}`;
  const current = Number(localStorage.getItem(key) ?? '0') || 0;
  if (serverSeq > current) {
    localStorage.setItem(key, String(serverSeq));
  }
}

export interface AttachedActionSig {
  seq: number;
  rHex: string;
  sHex: string;
}

/**
 * 为动作生成 (seq, sig)。sk/wasm 缺失或签名抛错时返回 null
 * （动作仍以未签名形态发出；是否拒绝由服务端 enforcement 开关决定）。
 */
export async function signTableAction(
  skHex: string | null,
  tableId: number | string,
  handId: number | null | undefined,
  action: 'fold' | 'check' | 'call' | 'raise',
  amount = 0,
): Promise<AttachedActionSig | null> {
  // 诊断告警：四条降级路径都必须在控制台可见——静默降级让
  // "no signed actions" 无法归因（2026-09-08 线上排查记录）。
  if (!skHex) {
    console.warn('[action-sig] unsigned: no sk (playerKeys missing)');
    return null;
  }
  // v2：hand_id 在签名域内——缺失（未拿到开局广播）时无法产出有效签名，
  // 返回 null（动作以未签名形态发出，服务端 enforcement 决定去留）。
  if (!handId) {
    console.warn('[action-sig] unsigned: no handId (shuffleState.hand_id and table.handId both missing)');
    return null;
  }
  const sign = await loadWasmSign();
  if (!sign) {
    console.warn('[action-sig] unsigned: wasm sign_action unavailable');
    return null;
  }
  try {
    const seq = nextSeq(tableId);
    const out = sign(skHex, Number(tableId), Number(handId), BigInt(seq), action, BigInt(amount)) as unknown;
    // serde_wasm_bindgen 把 JSON 对象序列化成 JS Map（非普通对象）——
    // 直接 out.r_hex 恒为 undefined，签名被静默丢弃（2026-09-08 线上
    // "no signed actions" 根因）。两种形状都兼容。
    const rHex = out instanceof Map ? out.get('r_hex') : (out as Record<string, unknown> | null)?.r_hex;
    const sHex = out instanceof Map ? out.get('s_hex') : (out as Record<string, unknown> | null)?.s_hex;
    if (typeof rHex !== 'string' || typeof sHex !== 'string') {
      console.warn('[action-sig] unsigned: sign_action returned unexpected shape', out);
      return null;
    }
    console.log(`[action-sig] signed action=${action} tableId=${Number(tableId)} handId=${Number(handId)} seq=${seq} amount=${amount}`);
    return { seq, rHex, sHex };
  } catch (e) {
    console.warn('[action-sig] unsigned: sign_action threw', e);
    return null;
  }
}

/** 把签名展开为 socket 消息字段（fold/check/call/raise 通吃）。
 * 形状必须与服务端 SimpleActionPayload / RaisePayload 对齐：
 * 嵌套 `sig: { rHex, sHex }`——平铺 rHex/sHex 会被服务端
 * #[serde(default)] 静默丢弃，动作以未签名落账（snip36 "no signed
 * actions"，2026-09-08 线上）。 */
export function sigToPayloadFields(sig: AttachedActionSig | null): Record<string, unknown> {
  if (!sig) return {};
  return { seq: sig.seq, sig: { rHex: sig.rHex, sHex: sig.sHex } };
}
