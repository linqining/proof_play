// 玩家密钥相关类型
import type { WasmClientPlayer } from '@linqining/client-wasm';

export interface PlayerContextType {
  playerKeys: WasmClientPlayer | null;
  pkProof: PkProofData | null;
  pkHex: string | null;
  skHex: string | null;
  gameId: string | null;
  playerName: string | null;
  wasmReady: boolean;
  /** 牌桌身份密钥模式（Part B）：random | passphrase | legacy。 */
  keyMode: 'random' | 'passphrase' | 'legacy' | null;
  setPlayerKeys: (
    keys: WasmClientPlayer,
    proof: PkProofData,
    gid: string,
    name: string,
  ) => void;
  clearPlayerKeys: () => void;
  getPlayerKeys: () => WasmClientPlayer | null;
  restoreSession: () => boolean;
  /** 口令派生切换（B1.5）：同一口令在任何设备恢复同一 pk。 */
  switchToPassphraseKey: (passphrase: string) => { ok: boolean; error?: string };
  /** 切回随机密钥（放弃口令可恢复性）。 */
  switchToRandomKey: () => { ok: boolean; error?: string };
}

export interface PkProofData {
  commitment: string;
  response: string;
  nonce: string;
}
