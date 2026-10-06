import React, { createContext, useState, useCallback, useEffect, useRef, useContext } from 'react';
import { PlayerContextType, PkProofData } from '../../types/player';
import init, { WasmClientPlayer } from '@linqining/client-wasm';
import wasmUrl from '@linqining/client-wasm/client_wasm_bg.wasm?url';
import authContext from '../auth/authContext';
import { logger } from '../../helpers/logger';
import { PlayerStorage, type PlayerKeyMode } from './playerStorage';

const PlayerContext = createContext<PlayerContextType | undefined>(undefined);

let wasmInitialized = false;
let wasmInitPromise: Promise<void> | null = null;

export async function ensureWasmReady() {
  if (wasmInitialized) return;

  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      await init({ module_or_path: wasmUrl });
      wasmInitialized = true;
      // Functional self-check: derives a real keypair + ownership proof.
      // Any protocol/curve breakage surfaces here, in the browser console.
      const selfTest = new WasmClientPlayer('wasm-selftest');
      const proof = selfTest.generate_pk_proof();
      const ok = typeof proof === 'string' ? JSON.parse(proof) : proof;
      if (!ok) throw new Error('pk proof self-test produced no output');
      logger.log('[wasm] ready — self-test pk:', selfTest.get_pk_hex().slice(0, 16) + '…');
    })();
  }

  await wasmInitPromise;
}

function parsePkProof(proofVal: unknown): PkProofData {
  if (typeof proofVal === 'string') {
    return JSON.parse(proofVal);
  }
  return proofVal as PkProofData;
}

const PlayerProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { walletAddress } = useContext(authContext)!;
  const [playerKeys, setPlayerKeysState] = useState<WasmClientPlayer | null>(null);
  const [pkProof, setPkProof] = useState<PkProofData | null>(null);
  const [pkHex, setPkHex] = useState<string | null>(null);
  const [skHex, setSkHex] = useState<string | null>(null);
  const [gameId, setGameId] = useState<string | null>(null);
  const [playerName, setPlayerName] = useState<string | null>(null);
  const [wasmReady, setWasmReady] = useState(false);
  const [keyMode, setKeyMode] = useState<PlayerKeyMode | null>(PlayerStorage.getKeyMode());
  const keysRef = useRef<WasmClientPlayer | null>(null);
  const restoreSessionRef = useRef<(() => boolean) | null>(null);
  const getPlayerKeysRef = useRef<(() => WasmClientPlayer | null) | null>(null);
  const prevWalletRef = useRef<string | null>(null);

  useEffect(() => {
    ensureWasmReady().then(() => {
      setWasmReady(true);
      if (restoreSessionRef.current) {
        const restored = restoreSessionRef.current();
        if (!restored && getPlayerKeysRef.current) {
          getPlayerKeysRef.current();
        }
      }
    }).catch((e: unknown) => {
      logger.error('[PlayerContext] Failed to initialize WASM:', e);
    });
  }, []);

  const setPlayerKeys = useCallback((keys: WasmClientPlayer, proof: PkProofData, gid: string, name: string) => {
    const pk = keys.get_pk_hex();
    const sk = keys.get_sk_hex();

    logger.log('[PlayerContext] Storing player keys');
    logger.log('[PlayerContext]   - Game ID:', gid);
    logger.log('[PlayerContext]   - Player name:', name);

    keysRef.current = keys;
    setPlayerKeysState(keys);
    setPkProof(parsePkProof(proof));
    setPkHex(pk);
    setSkHex(sk);
    setGameId(gid);
    setPlayerName(name);

    PlayerStorage.setSk(sk);
    PlayerStorage.setPk(pk);
    PlayerStorage.setPlayerName(name);
    PlayerStorage.setLastGameId(gid);
  }, []);

  const clearPlayerKeys = useCallback(() => {
    PlayerStorage.clearAll();

    keysRef.current = null;
    setPlayerKeysState(null);
    setPkProof(null);
    setPkHex(null);
    setSkHex(null);
    setGameId(null);
    setPlayerName(null);

    logger.log('[PlayerContext] Cleared all player data');
  }, []);

  // 密钥来源分发（docs/design/SETTLEMENT_PRIVACY_PLAN.md Part B）：
  // - 默认 new_random()：CSPRNG 随机，与钱包零派生关系（对手不可从钱包
  //   地址算出 pk）；
  // - 旧 wasm pkg 无 new_random 导出时回退钱包派生（迁移期兼容）；
  // - 口令派生走 switchToPassphraseKey（B1.5，面板触发）。
  const generateRandomKeys = useCallback((): WasmClientPlayer | null => {
    const wasmAny = WasmClientPlayer as unknown as {
      new_random?: () => WasmClientPlayer;
    };
    if (typeof wasmAny.new_random === 'function') {
      PlayerStorage.setKeyMode('random');
      return wasmAny.new_random();
    }
    logger.warn('[PlayerContext] wasm lacks new_random — falling back to wallet derivation (legacy)');
    if (!walletAddress) return null;
    PlayerStorage.setKeyMode('legacy');
    return WasmClientPlayer.new_with_wallet_address(walletAddress);
  }, [walletAddress]);

  const getPlayerKeys = useCallback((): WasmClientPlayer | null => {
    if (keysRef.current) {
      return keysRef.current;
    }

    if (!wasmInitialized) {
      logger.error('[PlayerContext] WASM not initialized');
      return null;
    }

    const storedSk = PlayerStorage.getSk();
    if (!storedSk) {
      logger.warn('[PlayerContext] No SK found in storage, generating a fresh random key (Part B)');
      const newKeys = generateRandomKeys();
      if (!newKeys) {
        logger.error('[PlayerContext] Cannot generate keys (no wasm random / no wallet fallback)');
        return null;
      }
      const sk = newKeys.get_sk_hex();
      const pk = newKeys.get_pk_hex();
      PlayerStorage.setSk(sk);
      PlayerStorage.setPk(pk);
      const restoredProof = parsePkProof(newKeys.generate_pk_proof());
      setPlayerKeys(newKeys, restoredProof, "", pk);
      return newKeys;
    }

    try {
      logger.log('[PlayerContext] Reconstructing player keys from SK...', storedSk);
      const reconstructedKeys = WasmClientPlayer.from_sk(storedSk);
      const restoredProof = parsePkProof(reconstructedKeys.generate_pk_proof());
      const pk = reconstructedKeys.get_pk_hex();
      const savedName = PlayerStorage.getPlayerName() || '';
      const savedGameId = PlayerStorage.getLastGameId() || '';
      setPlayerKeys(reconstructedKeys, restoredProof, savedGameId, savedName);
      logger.log('[PlayerContext] Successfully reconstructed player keys');
      return reconstructedKeys;
    } catch (e) {
      logger.error('[PlayerContext] Failed to reconstruct player keys:', e);
      return null;
    }
  }, [setPlayerKeys, generateRandomKeys]);

  const restoreSession = useCallback((): boolean => {
    const savedGameId = PlayerStorage.getLastGameId();
    const savedSk = PlayerStorage.getSk();
    const savedName = PlayerStorage.getPlayerName();

    if (!savedSk) {
      return false;
    }

    if (keysRef.current) return true;

    if (!wasmInitialized) {
      logger.error('[PlayerContext] WASM not initialized');
      return false;
    }

    try {
      logger.log('[PlayerContext] Restoring player session from storage...');
      const restoredKeys = WasmClientPlayer.from_sk(savedSk);
      const restoredProof = parsePkProof(restoredKeys.generate_pk_proof());

      setPlayerKeys(restoredKeys, restoredProof, savedGameId || '', savedName || '');
      logger.log('[PlayerContext] Player session restored successfully!');
      return true;
    } catch (e) {
      logger.error('[PlayerContext] Failed to restore player session:', e);
      PlayerStorage.clearLastGameId();
      return false;
    }
  }, [setPlayerKeys]);

  useEffect(() => {
    restoreSessionRef.current = restoreSession;
    getPlayerKeysRef.current = getPlayerKeys;
  }, [restoreSession, getPlayerKeys]);

  // 钱包地址变化时，重新生成密钥（与钱包一一对应）
  useEffect(() => {
    if (!wasmReady || !walletAddress) return;
    // 首次或钱包未变化时跳过
    if (prevWalletRef.current === walletAddress) return;
    const prevWallet = prevWalletRef.current;
    prevWalletRef.current = walletAddress;

    // 非首次切换钱包：清除旧密钥，生成新的随机身份（Part B：密钥不跟随钱包派生）
    if (prevWallet !== null) {
      logger.log('[PlayerContext] Wallet address changed, regenerating keys');
      clearPlayerKeys();
      const newKeys = generateRandomKeys();
      if (!newKeys) return;
      const sk = newKeys.get_sk_hex();
      const pk = newKeys.get_pk_hex();
      PlayerStorage.setSk(sk);
      PlayerStorage.setPk(pk);
      const proof = parsePkProof(newKeys.generate_pk_proof());
      setPlayerKeys(newKeys, proof, "", pk);
    }
  }, [walletAddress, wasmReady, clearPlayerKeys, setPlayerKeys, generateRandomKeys]);

  /** 口令派生切换（B1.5）：同一口令在任何设备恢复同一 pk。 */
  const switchToPassphraseKey = useCallback((passphrase: string): { ok: boolean; error?: string } => {
    if (!wasmReady) return { ok: false, error: 'wasm 未就绪' };
    if (!passphrase || passphrase.length < 8) return { ok: false, error: '口令至少 8 个字符' };
    const wasmAny = WasmClientPlayer as unknown as {
      new_with_passphrase?: (p: string) => WasmClientPlayer;
    };
    if (typeof wasmAny.new_with_passphrase !== 'function') {
      return { ok: false, error: '当前 wasm 版本不支持口令派生' };
    }
    const keys = wasmAny.new_with_passphrase(passphrase);
    const proof = parsePkProof(keys.generate_pk_proof());
    setPlayerKeys(keys, proof, PlayerStorage.getLastGameId() || '', PlayerStorage.getPlayerName() || '');
    PlayerStorage.setKeyMode('passphrase');
    setKeyMode('passphrase');
    logger.log('[PlayerContext] switched to passphrase-derived key, pk:', keys.get_pk_hex().slice(0, 16) + '…');
    return { ok: true };
  }, [wasmReady, setPlayerKeys]);

  /** 切回随机密钥（放弃口令可恢复性）。 */
  const switchToRandomKey = useCallback((): { ok: boolean; error?: string } => {
    const keys = generateRandomKeys();
    if (!keys) return { ok: false, error: '无法生成随机密钥（wasm 未就绪）' };
    const proof = parsePkProof(keys.generate_pk_proof());
    setPlayerKeys(keys, proof, PlayerStorage.getLastGameId() || '', PlayerStorage.getPlayerName() || '');
    setKeyMode(PlayerStorage.getKeyMode());
    return { ok: true };
  }, [generateRandomKeys, setPlayerKeys]);

  useEffect(() => {
    logger.log('[PlayerContext] Context updated:', {
      hasKeys: !!playerKeys,
      gameId,
      playerName,
      wasmReady,
    });
  }, [playerKeys, gameId, playerName, wasmReady]);

  return (
    <PlayerContext.Provider
      value={{
        playerKeys,
        pkProof,
        pkHex,
        skHex,
        gameId,
        playerName,
        wasmReady,
        keyMode,
        setPlayerKeys,
        clearPlayerKeys,
        getPlayerKeys,
        restoreSession,
        switchToPassphraseKey,
        switchToRandomKey,
      }}
    >
      {children}
    </PlayerContext.Provider>
  );
};

export { PlayerContext };
export default PlayerProvider;
