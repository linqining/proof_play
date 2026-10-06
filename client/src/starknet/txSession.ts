// P1-2 会话委托：VM 层交易签名会话密钥的客户端管理。
//
// 密钥是随机新鲜钥（与钱包地址零派生关系——知道地址推不出任何凭据）：
// sk 存 localStorage（重连恢复、零钱包交互），pk（Stark 曲线 32B 压缩点，
// 本就是规范域元素）用于两处——
//   1. 买入 multicall 里 vault.set_session_tx_pk 链上登记（caller-gated，
//      与 deposit 同笔原子生效，latest-wins）；
//   2. sit_down payload 的 sessionTxPk 声明（服务端经 vault
//      active_session_tx_pk view 逐字节对拍核验，通过后成为该座位 VM 层
//      交易签名的验证锚，见 texas/src/starknet/lock.rs verify_session_tx_pk）。
// wasm 能力缺失（旧 pkg）时返回 null：买入退化为不带登记，服务端过渡期
// fail-open（texas/src/socket/handlers.rs 的 P1-2 注释）。

import { logger } from '../helpers/logger';

interface WasmTxSessionLike {
  get_sk_hex(): string;
  get_pk_hex(): string;
}

/** 会话有效期：7 天（链上 active_session_tx_pk 过期即视为未登记）。 */
export const TX_SESSION_TTL_SECS = 7 * 24 * 60 * 60;

const SK_STORAGE_KEY = 'zgame_tx_session_sk';

let sessionPromise: Promise<{ skHex: string; pkHex: string } | null> | null = null;

/** 惰性初始化（整个页面生命周期只跑一次）；失败不抛出，降级为 null。 */
export function ensureTxSession(): Promise<{ skHex: string; pkHex: string } | null> {
  if (!sessionPromise) {
    sessionPromise = (async () => {
      try {
        const wasm = (await import('@linqining/client-wasm')) as unknown as {
          WasmTxSession: {
            new (): WasmTxSessionLike;
            from_sk(skHex: string): WasmTxSessionLike;
          };
        };
        let session: WasmTxSessionLike | null = null;
        let skHex: string | null = null;
        try {
          skHex = window.localStorage.getItem(SK_STORAGE_KEY);
        } catch {
          // 隐私模式等 localStorage 不可用：退化为一次性会话钥（不持久化）
        }
        if (skHex) {
          try {
            session = wasm.WasmTxSession.from_sk(skHex);
          } catch (e) {
            logger.warn('[tx-session] stored sk invalid, regenerating:', e);
            session = null;
          }
        }
        if (!session) {
          session = new wasm.WasmTxSession();
          try {
            window.localStorage.setItem(SK_STORAGE_KEY, session.get_sk_hex());
          } catch {
            // localStorage 不可用：密钥仅活在本页会话
          }
        }
        const out = { skHex: session.get_sk_hex(), pkHex: session.get_pk_hex() };
        logger.log('[tx-session] ready, pk =', out.pkHex);
        return out;
      } catch (e) {
        logger.warn('[tx-session] wasm unavailable — session delegation disabled:', e);
        return null;
      }
    })();
  }
  return sessionPromise;
}

/** 会话公钥（32B 压缩点 hex）；wasm 不可用时 null。买入登记与 sit_down
 *  声明共用同一把钥（服务端要求两者逐字节一致）。 */
export async function ensureTxSessionPkHex(): Promise<string | null> {
  return (await ensureTxSession())?.pkHex ?? null;
}

/**
 * compress() 编码 = x 坐标（32B 大端，恒 < 2^251）+ byte[0] 高位的 y 奇偶
 * 标志（0x80）。该标志位会让数值越出 felt252（P < 2^252 的最高位之下），
 * 因此链上登记（vault.set_session_tx_pk 的 felt 入参）必须用剥掉标志的
 * x-only 形式；完整 flagged 形式走 sit_down 的 sessionTxPk 声明，服务端
 * 按 x-only 掩码对拍（texas/src/starknet/lock.rs）。
 */
export function txPkFeltHex(pkHex: string): string | null {
  const body = pkHex.trim().replace(/^0x/i, '');
  if (body.length !== 64 || !/^[0-9a-fA-F]+$/.test(body)) return null;
  const firstByte = parseInt(body.slice(0, 2), 16) & 0x7f;
  return firstByte.toString(16).padStart(2, '0') + body.slice(2);
}
