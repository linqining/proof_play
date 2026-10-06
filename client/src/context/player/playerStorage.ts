// Typed wrapper around localStorage for player-related keys.
// Centralizes the raw 'sk' / 'pk' / 'player_name' / 'last_game_id' string keys
// so they are defined in exactly one place.

const STORAGE_KEYS = {
  SK: 'sk',
  PK: 'pk',
  PLAYER_NAME: 'player_name',
  LAST_GAME_ID: 'last_game_id',
  KEY_MODE: 'poker.keyMode',
} as const;

/** 牌桌身份密钥模式（docs/design/SETTLEMENT_PRIVACY_PLAN.md Part B）。
 * - random：CSPRNG 随机（默认），与钱包零派生关系，丢 localStorage 即丢身份；
 * - passphrase：口令派生（B1.5），凭口令跨设备恢复同一 pk；
 * - legacy：旧版钱包地址派生（存量用户，只读兼容）。 */
export type PlayerKeyMode = 'random' | 'passphrase' | 'legacy';

export const PlayerStorage = {
  getSk(): string | null {
    return localStorage.getItem(STORAGE_KEYS.SK);
  },
  setSk(sk: string): void {
    localStorage.setItem(STORAGE_KEYS.SK, sk);
  },

  getKeyMode(): PlayerKeyMode | null {
    const v = localStorage.getItem(STORAGE_KEYS.KEY_MODE);
    return v === 'random' || v === 'passphrase' || v === 'legacy' ? v : null;
  },
  setKeyMode(mode: PlayerKeyMode): void {
    localStorage.setItem(STORAGE_KEYS.KEY_MODE, mode);
  },

  getPk(): string | null {
    return localStorage.getItem(STORAGE_KEYS.PK);
  },
  setPk(pk: string): void {
    localStorage.setItem(STORAGE_KEYS.PK, pk);
  },

  getPlayerName(): string | null {
    return localStorage.getItem(STORAGE_KEYS.PLAYER_NAME);
  },
  setPlayerName(name: string): void {
    localStorage.setItem(STORAGE_KEYS.PLAYER_NAME, name);
  },

  getLastGameId(): string | null {
    return localStorage.getItem(STORAGE_KEYS.LAST_GAME_ID);
  },
  setLastGameId(gid: string): void {
    localStorage.setItem(STORAGE_KEYS.LAST_GAME_ID, gid);
  },
  clearLastGameId(): void {
    localStorage.removeItem(STORAGE_KEYS.LAST_GAME_ID);
  },

  clearAll(): void {
    localStorage.removeItem(STORAGE_KEYS.SK);
    localStorage.removeItem(STORAGE_KEYS.PK);
    localStorage.removeItem(STORAGE_KEYS.PLAYER_NAME);
    localStorage.removeItem(STORAGE_KEYS.LAST_GAME_ID);
  },
};
