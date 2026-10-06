import { useEffect, useState, useCallback, useRef } from 'react';
import httpClient from '../helpers/httpClient';
import setAuthToken from '../helpers/setAuthToken';
import { getToken } from '../helpers/getToken';
import { useGlobalContext } from '../context/global/globalContext';
import { useAccount, useConnect, useDisconnect } from '@starknet-react/core';
import { getStrkBalance } from '../starknet/starknetGameActions';
import { starknetConfig } from '../starknet/config';
import { activeAccount, activeAddress } from '../starknet/devAccount';
import {
  zchainAddress,
  zchainConnect,
  zchainSignLogin,
  clearZChainSession,
  isZChainSession,
} from '../starknet/zchainWallet';
import {
  monadAddress,
  monadConnect,
  monadPersonalSign,
  monadLoginMessageHash,
  clearMonadSession,
  isMonadSession,
} from '../starknet/monadWallet';
import type { AuthMethod } from '../context/auth/authContext';
import { logger } from '../helpers/logger';

interface UseAuthReturn {
  isLoggedIn: boolean;
  logout: () => void;
  loadUser: (token: string) => Promise<void>;
  walletAddress: string | null;
  disconnectWallet: () => void;
  authMethod: AuthMethod;
  loginWithZChain: () => Promise<void>;
  loginWithMonad: () => Promise<void>;
}

/** Typed-data domain for the login message (SNIP-12 revision 1). */
const LOGIN_DOMAIN = {
  name: 'zgame',
  version: '1',
  chainId: starknetConfig.chainId,
  revision: '1',
};

const useAuth = (): UseAuthReturn => {
  const token = getToken();
  if (token) setAuthToken(token);

  const {
    setId,
    setIsLoading,
    setUserName,
    setEmail,
    setChipsAmount,
    setStrkBalance,
  } = useGlobalContext();

  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [walletAddress, setWalletAddress] = useState<string | null>(
    localStorage.getItem('walletAddress')
  );
  const [authMethod, setAuthMethod] = useState<AuthMethod>(
    (localStorage.getItem('authMethod') as AuthMethod) || null
  );

  const { address: connectedAddress, account: connectedAccount } = useAccount();
  // Cartridge 文档模型：登出必须 disconnect Controller（断开 keychain 会话），
  // 否则连接仍在、自动重登立即登回同一账号，永远换不了用户。
  const { disconnect: disconnectConnector } = useDisconnect();
  // ZChain 钱包会话：身份来自 window.zchain 扩展（无 Starknet account）。
  // 无 Starknet 连接地址时才接管，避免与注入钱包互抢。
  const [zchainAddr, setZchainAddr] = useState<string | null>(zchainAddress());
  const zchainActive = !connectedAddress && zchainAddr !== null;
  // Monad 钱包会话：身份来自 EIP-1193 window.ethereum（EVM 地址，
  // 同样无 Starknet account）。优先级与 ZChain 并列：注入钱包 > ZChain/Monad 会话。
  const [monadAddr, setMonadAddr] = useState<string | null>(monadAddress());
  const monadActive = !connectedAddress && monadAddr !== null;
  // 连接的钱包（Ready/Cartridge）优先，ZChain/Monad 扩展会话次之，dev 直签兜底。
  const address = zchainActive
    ? zchainAddr
    : monadActive
      ? monadAddr
      : activeAddress(connectedAddress);
  const account = activeAccount(connectedAccount);
  const { connectAsync, connectors } = useConnect();
  // 登出过渡守卫：disconnect 是异步的，期间 address 尚未清空，自动重登
  // effect 会立刻登回原账号（表现为"退出登录无效"）。用 ref + sessionStorage
  // 标记压制，直到用户在 Sign In 里显式选择钱包（或连接成功）才解除。
  const loggingOutRef = useRef(false);
  const LOGGED_OUT_FLAG = 'poker.loggedOut';

  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      setIsLoading(true);
      // 静默重连：autoConnect 已禁用（防止 Cartridge 被旧记录静默重连），
      // 这里只重连注入类钱包（Ready）。Cartridge 由买入成功后的
      // initGameController 负责初始化，不走这里。
      const last = localStorage.getItem('lastUsedConnector');
      if (last === 'argentX' || last === 'ready') {
        const connector = connectors.find((c) => c.id === last);
        if (connector && (await Promise.resolve(connector.available()).catch(() => false))) {
          connectAsync({ connector }).catch((e) =>
            logger.warn('[Auth] injected wallet silent reconnect failed:', e)
          );
        }
      }
      const storedToken = getToken();
      if (!storedToken) {
        localStorage.removeItem('walletAddress');
        localStorage.removeItem('authMethod');
        setWalletAddress(null);
        setAuthMethod(null);
      }
      if (storedToken) await loadUser(storedToken);
      if (!cancelled) setIsLoading(false);
    };
    init();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync wallet address from starknet-react
  useEffect(() => {
    if (address) {
      setWalletAddress(address);
      localStorage.setItem('walletAddress', address);
    } else {
      setWalletAddress(null);
      localStorage.removeItem('walletAddress');
    }
  }, [address]);

  // Refresh STRK balance whenever the address changes（ZChain 会话无
  // Starknet 链上余额，直接置空跳过查询）
  useEffect(() => {
    if (!address) {
      setStrkBalance(null);
      return;
    }
    if (isZChainSession() || isMonadSession()) {
      setStrkBalance(null);
      return;
    }
    let cancelled = false;
    (async () => {
      const bal = await getStrkBalance(address);
      if (!cancelled) setStrkBalance(bal);
    })();
    return () => { cancelled = true; };
  }, [address, setStrkBalance]);

  // 会话过期统一处理：httpClient 在 401 时派发 zgame:session-expired，
  // 这里清理前端登录态（等同 logout，但不调后端——后端已不认识这个 token）。
  useEffect(() => {
    const onSessionExpired = () => {
      logger.warn('[Auth] session expired — clearing login state');
      localStorage.removeItem('token');
      localStorage.removeItem('walletAddress');
      localStorage.removeItem('authMethod');
      setWalletAddress(null);
      setAuthToken(null);
      setIsLoggedIn(false);
      setId(null);
      setUserName(null);
      setEmail(null);
      setChipsAmount(null);
      setStrkBalance(null);
      setAuthMethod(null);
    };
    window.addEventListener('zgame:session-expired', onSessionExpired);
    return () => window.removeEventListener('zgame:session-expired', onSessionExpired);
  }, [setId, setUserName, setEmail, setChipsAmount, setStrkBalance]);

  // Auto-authenticate with the backend after wallet connection。
  // 显式登出后（sessionStorage 标记在位）不再自动登录——用户必须通过
  // Sign In 显式选择钱包（如 Ready），否则永远换不了账号。
  useEffect(() => {
    if (loggingOutRef.current) return;
    if (sessionStorage.getItem(LOGGED_OUT_FLAG) === '1') return;
    if (address && !isLoggedIn && account) {
      const storedToken = getToken();
      if (!storedToken) {
        authenticateWithWallet(address, account).catch((e) =>
          logger.error('[Auth] wallet auth failed:', e)
        );
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address, isLoggedIn, account]);

  /** 显式登录动作（Sign In 弹窗连接钱包时调用）：解除登出标记。 */
  const clearLoggedOutFlag = useCallback((): void => {
    sessionStorage.removeItem(LOGGED_OUT_FLAG);
    loggingOutRef.current = false;
  }, []);

  const authenticateWithWallet = async (
    addr: string,
    acct: NonNullable<typeof account>,
  ): Promise<void> => {
    // 走到钱包认证 = 用户显式登录，解除登出压制
    clearLoggedOutFlag();
    setIsLoading(true);
    try {
      // SNIP-12 rev1 typed message: 服务端需要 messageHash 做 isValidSignature 验证。
      // 约束来自 Cartridge controller wasm 内嵌的 starknet-core 严格解析：
      // - domain 类型名必须是 "StarknetDomain"（小写 net）且带 revision 字段；
      // - 只支持 felt/shortstring/ContractAddress/timestamp 等内置类型（无 ByteArray）；
      // - 每个字段值必须能编码成单个 felt（不能放长文本）。
      // 服务端只校验 (address, messageHash, signature)，不解析 message 内容。
      const message = `zgame-login:${addr}:${Date.now()}`;
      const typedDataObj = {
        domain: LOGIN_DOMAIN,
        types: {
          StarknetDomain: [
            { name: 'name', type: 'shortstring' },
            { name: 'version', type: 'shortstring' },
            { name: 'chainId', type: 'shortstring' },
            { name: 'revision', type: 'shortstring' },
          ],
          Message: [
            { name: 'action', type: 'shortstring' },
            { name: 'address', type: 'ContractAddress' },
            { name: 'timestamp', type: 'timestamp' },
          ],
        },
        primaryType: 'Message',
        message: {
          action: 'zgame-login',
          address: addr,
          timestamp: Math.floor(Date.now() / 1000),
        },
      };
      const signature = await acct.signMessage(typedDataObj);
      const typedDataMod = await import('starknet');
      const messageHash = typedDataMod.typedData.getMessageHash(typedDataObj, addr);
      // plain Account（dev 直签）的 signMessage / getMessageHash 返回 bigint，
      // axios 的 JSON 序列化无法处理 bigint（同步抛
      // "Do not know how to serialize a BigInt"）——统一转成 felt 字符串。
      const signatureFelts = Array.isArray(signature)
        ? signature.map((s) => String(s))
        : [String(signature)];

      const res = await httpClient.post('/auth/wallet', {
        address: addr,
        messageHash: String(messageHash),
        signature: signatureFelts,
        message,
      });

      const backendToken = res.data.token;
      if (backendToken) {
        localStorage.setItem('token', backendToken);
        setAuthToken(backendToken);
        await loadUser(backendToken);
        setAuthMethod('wallet');
        localStorage.setItem('authMethod', 'wallet');
      }
    } catch (error) {
      logger.error('[Auth] Wallet authentication failed:', error);
      // 后端校验失败原因（如"钱包地址尚未激活"）直接透出给用户，
      // 否则签名失败只有控制台日志，用户无从知晓。
      const backendMsg =
        error && typeof error === 'object' && 'response' in error
          ? (error as { response?: { data?: { error?: string } } }).response?.data
              ?.error
          : undefined;
      if (backendMsg) {
        window.alert(backendMsg);
      }
    }
    setIsLoading(false);
  };

  /**
   * Monad 钱包登录（EIP-1193）：切/加 Monad 测试网 → eth_requestAccounts →
   * personal_sign（EIP-191，钱包弹窗确认）→ 以本地复算摘要作 messageHash
   * 走 /auth/wallet。服务端口径与 ZChain 路径相同：默认
   * STARKNET_AUTH_STRICT=false 的 dev 模式跳过链上验签
   * （texas/src/starknet/auth.rs:31-33）；strict 模式只能验 Starknet
   * isValidSignature，EVM 登录在该模式下不可用——部署 ZChain dev 栈时成立。
   */
  const loginWithMonad = async (): Promise<void> => {
    clearLoggedOutFlag();
    setIsLoading(true);
    try {
      const addr = await monadConnect();
      const message = `zgame-login:${addr}:${Date.now()}`;
      const signature = await monadPersonalSign(addr, message);
      const messageHash = monadLoginMessageHash(message);
      setMonadAddr(addr);
      const res = await httpClient.post('/auth/wallet', {
        address: addr,
        messageHash,
        signature: [signature],
        message,
      });
      const backendToken = res.data.token;
      if (backendToken) {
        localStorage.setItem('token', backendToken);
        setAuthToken(backendToken);
        await loadUser(backendToken);
        setAuthMethod('wallet');
        localStorage.setItem('authMethod', 'wallet');
      }
    } catch (error) {
      logger.error('[Auth] Monad wallet login failed:', error);
      window.alert(`Monad 钱包登录失败：${(error as Error)?.message ?? error}`);
    }
    setIsLoading(false);
  };

  /**
   * ProofPlay 钱包登录：连接扩展（弹窗确认）→ 结构化操作签名（弹窗确认）→
   * 以摘要作为凭证走 /auth/wallet（服务端 dev 模式跳过链上验签；
   * STARKNET_AUTH_STRICT=true 时需链上可验，ZChain 路径仅用于 dev 部署）。
   */
  const loginWithZChain = async (): Promise<void> => {
    clearLoggedOutFlag();
    setIsLoading(true);
    try {
      const addr = await zchainConnect();
      const digest = await zchainSignLogin(addr);
      setZchainAddr(addr);
      const res = await httpClient.post('/auth/wallet', {
        address: addr,
        messageHash: digest,
        signature: [digest],
        message: `zchain-login:${addr}:${Date.now()}`,
      });
      const backendToken = res.data.token;
      if (backendToken) {
        localStorage.setItem('token', backendToken);
        setAuthToken(backendToken);
        await loadUser(backendToken);
        setAuthMethod('wallet');
        localStorage.setItem('authMethod', 'wallet');
      }
    } catch (error) {
      logger.error('[Auth] ZChain wallet login failed:', error);
      const e = error as { code?: string; message?: string };
      window.alert(`ProofPlay 钱包登录失败：${e?.code ? `${e.code}: ` : ''}${e?.message ?? error}`);
    }
    setIsLoading(false);
  };

  const loadUser = async (token: string): Promise<void> => {    try {
      const res = await httpClient.get('/auth');
      const { _id, name, address: userAddress, chipsAmount } = res.data;
      setIsLoggedIn(true);
      setId(_id);
      setUserName(name);
      if (userAddress) {
        setWalletAddress(userAddress);
        localStorage.setItem('walletAddress', userAddress);
      }
      setChipsAmount(chipsAmount ?? 0);
    } catch (error) {
      // 登录会话已失效（401 token 无效 / 404 服务端重启清空了会话用户）：
      // 彻底清理前端登录态。但只在失败的 token 仍是当前存储 token 时清理——
      // 若自动重登已换发新 token（竞态），旧 token 的迟到失败必须忽略，
      // 否则会把新登录态清掉（Sign In 闪退）。
      const status = (error as { response?: { status?: number } })?.response?.status;
      const failedToken = getToken();
      if (failedToken !== token) {
        logger.warn('loadUser failed for a stale token — ignoring (already re-authenticated)');
        return;
      }
      logger.warn('loadUser failed (status=%s) — clearing login state:', status, error);
      localStorage.removeItem('token');
      localStorage.removeItem('walletAddress');
      localStorage.removeItem('authMethod');
      clearZChainSession();
      setZchainAddr(null);
      clearMonadSession();
      setMonadAddr(null);
      setAuthToken(null);
      setIsLoggedIn(false);
      setWalletAddress(null);
      setAuthMethod(null);
      setId(null);
      setUserName(null);
      setChipsAmount(null);
    }
  };

  const logout = useCallback((): void => {
    localStorage.removeItem('token');
    localStorage.removeItem('walletAddress');
    localStorage.removeItem('authMethod');
    setIsLoggedIn(false);
    setId(null);
    setUserName(null);
    setEmail(null);
    setChipsAmount(null);
    setStrkBalance(null);
    setAuthMethod(null);
  }, [setId, setUserName, setEmail, setChipsAmount, setStrkBalance]);

  const disconnectWallet = useCallback((): void => {
    const storedToken = getToken();
    if (storedToken) {
      httpClient.post('/auth/wallet/logout', {}).catch((err) => {
        logger.error('wallet_logout backend call failed:', err);
      });
    }
    // ZChain 钱包会话：清理本地会话状态（扩展侧授权由用户在扩展里管理）。
    clearZChainSession();
    setZchainAddr(null);
    // Monad 钱包会话：同款清理（EIP-1193 授权由用户在钱包里管理）。
    clearMonadSession();
    setMonadAddr(null);
    // 登出三步，顺序关键：
    // 1) 先立"登出中"标记 + 清本地登录态——自动重登 effect 立即失效；
    // 2) 再异步断开钱包连接（disconnectConnector 是 Promise，不 await 会
    //    留下 address，自动重登 effect 看到旧 address 立刻登回原账号）；
    // 3) 断开完成后写入"已登出"标记（sessionStorage），此后即使 dev 兜底
    //    账户存在也不再自动登录——用户必须经 Sign In 显式选择钱包。
    loggingOutRef.current = true;
    sessionStorage.setItem(LOGGED_OUT_FLAG, '1');
    logout();
    setWalletAddress(null);
    Promise.resolve()
      .then(() => disconnectConnector())
      .catch((err) => logger.warn('connector disconnect failed:', err))
      .finally(() => {
        // disconnect 完成后再统一清一次，覆盖断开过程中残留的地址状态
        logout();
        setWalletAddress(null);
      });
  }, [logout, disconnectConnector]);

  // 已登录状态下连接了新钱包（如从 Cartridge 切到 Ready）：自动以新钱包
  // 重新认证，身份随之切换——无需先手动登出。
  const prevAuthedAddressRef = useRef<string | null>(null);
  useEffect(() => {
    if (loggingOutRef.current) return;
    if (!address || !account) {
      prevAuthedAddressRef.current = null;
      return;
    }
    if (!isLoggedIn) {
      prevAuthedAddressRef.current = address;
      return;
    }
    if (prevAuthedAddressRef.current === null) {
      prevAuthedAddressRef.current = address;
      return;
    }
    if (prevAuthedAddressRef.current !== address) {
      logger.log('[Auth] wallet switched:', prevAuthedAddressRef.current, '→', address, '— re-authenticating');
      prevAuthedAddressRef.current = address;
      localStorage.removeItem('token');
      setAuthToken(null);
      setIsLoggedIn(false);
      authenticateWithWallet(address, account).catch((e) =>
        logger.error('[Auth] re-auth after wallet switch failed:', e)
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address, isLoggedIn, account]);

  return {
    isLoggedIn,
    logout,
    loadUser,
    walletAddress,
    disconnectWallet,
    authMethod,
    loginWithZChain,
    loginWithMonad,
  };
};

export default useAuth;