import React, { useContext, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import styled from 'styled-components';
import { useAccount, useConnect, useDisconnect } from '@starknet-react/core';
import { activeAddress } from '../../starknet/devAccount';
import { isMonadProvider } from '../../starknet/monadWallet';
import authContext from '../../context/auth/authContext';
import contentContext from '../../context/content/contentContext';
import CloseButton from '../buttons/CloseButton';
import ModalShell from '../modals/ModalShell';
import strkLogoSvg from '/strk-logo.svg';

const IconWrapper = styled.div`
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  z-index: 1;
`;

const ModalContent = styled.div`
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 0.875rem;
`;

const ModalHeading = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.2rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: -0.02em;
  margin: 0;
`;

const LoginSection = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  width: 100%;
`;

const WalletButton = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.65rem 0.875rem;
  border-radius: ${({ theme }) => theme.radius.md};
  border: 1px solid #d1d5db;
  background: ${({ theme }) => theme.colors.lightestBg};
  font-size: 0.95rem;
  font-weight: 600;
  color: #1f2937;
  cursor: pointer;
  transition:
    background-color 0.2s ease,
    border-color 0.2s ease,
    transform 0.1s ease;
  min-height: 44px;

  &:hover {
    background: ${({ theme }) => theme.colors.lightBg};
    border-color: #94a3b8;
  }

  &:active {
    transform: scale(0.98);
  }

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .login-btn-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
`;

const StrkLogo = styled.img`
  width: 18px;
  height: 18px;
  display: block;
  flex-shrink: 0;
`;

// 未装钱包时的引导：样式复用 WalletButton，只是渲染成外链 <a>
const InstallButton = styled(WalletButton).attrs({ as: 'a' })`
  text-decoration: none;
`;

const RecheckButton = styled.button`
  width: 100%;
  padding: 0.5rem 0.875rem;
  border: none;
  border-radius: ${({ theme }) => theme.radius.md};
  background: transparent;
  font-size: 0.82rem;
  font-weight: 600;
  color: #6b7280;
  cursor: pointer;
  transition: color 0.2s ease;
  min-height: 36px;

  &:hover {
    color: #374151;
    text-decoration: underline;
  }
`;

const Note = styled.div`
  font-size: 0.72rem;
  /* softText 而非 #94a3b8：白底对比度 4.8:1，满足 WCAG AA */
  color: ${({ theme }) => theme.colors.softText};
  text-align: center;
  margin-top: 0.25rem;
  line-height: 1.4;
`;

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

// Ready X（原 Argent X）Chrome 商店官方地址
const READY_CHROME_STORE_URL =
  'https://chromewebstore.google.com/detail/ready-x/dlcobpjiigpikoobohmabehhmhfoodbb';

const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const isLoggedIn = useContext(authContext)!.isLoggedIn;
  const { getLocalizedString: t } = useContext(contentContext)!;
  const { loginWithZChain, loginWithMonad } = useContext(authContext)!;
  const [zchainPending, setZchainPending] = useState(false);
  const [monadPending, setMonadPending] = useState(false);
  const connected = useAccount();
  // 连接的钱包（Ready/Cartridge）优先，dev 直签账户仅作无钱包时兜底
  const address = activeAddress(connected.address);
  const { connect, connectors, connectAsync, isPending, error } = useConnect();
  const { disconnect } = useDisconnect();

  // 只渲染已安装的注入钱包（Ready 未安装时两个注入 id 都探不到 → 不显示
  // 死按钮；Cartridge 为内嵌 connector，恒可用）。
  // 登录只保留注入钱包（Ready）。Cartridge 不再作为登录选项——它在买入
  // 成功后由应用自动初始化（游戏交互签名），不承担登录/买入/swap/领取。
  // 初始为空数组：探测是异步的，若初始放全量 connectors 会先闪一帧
  // Cartridge 等不可用按钮再消失。
  type Connector = (typeof connectors)[number];
  const [availableConnectors, setAvailableConnectors] = useState<Connector[]>([]);
  // 探测完成标记：完成且结果为空 → 展示"安装 Ready"引导。
  // probeTick 用于"重新检测"（装完插件后不必整页刷新）。
  const [probed, setProbed] = useState(false);
  const [probeTick, setProbeTick] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setProbed(false);
    Promise.all(
      connectors.map(async (connector) => ({
        connector,
        available:
          /argentX|^ready$/i.test(connector.id) &&
          (await Promise.resolve(connector.available()).catch(() => false)),
      })),
    ).then((results) => {
      if (cancelled) return;
      setAvailableConnectors(results.filter((r) => r.available).map((r) => r.connector));
      setProbed(true);
    });
    return () => {
      cancelled = true;
    };
  }, [connectors, probeTick]);

  useEffect(() => {
    if (isOpen && isLoggedIn) {
      onClose();
    }
  }, [isOpen, isLoggedIn, onClose]);

  // If a wallet is already connected but we're not logged in, the auth flow
  // will trigger automatically via useAuth. We close the modal in that case.
  // 注意：只按"真实连接的钱包地址"判断 —— dev 直签账户（VITE_DEV_ACCOUNT_*）
  // 的 address 恒非空，不能拿来关弹窗（否则弹窗一打开就闪退）。
  useEffect(() => {
    if (isOpen && connected.address) {
      onClose();
    }
  }, [isOpen, connected.address, onClose]);

  const handleConnect = async (connector: (typeof connectors)[number]) => {
    try {
      // 显式选择钱包 = 用户登录意图，解除登出压制（否则自动登录被跳过）
      sessionStorage.removeItem('poker.loggedOut');
      await connectAsync({ connector });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[LoginModal] Starknet wallet connect failed:', e);
    }
  };

  if (!isOpen) return null;

  return ReactDOM.createPortal(
    <ModalShell
      width="360px"
      onBackdropClick={onClose}
      ariaLabel={t('login_sign-in')}
    >
      <IconWrapper>
        <CloseButton clickHandler={onClose} ariaLabel="Close login modal" />
      </IconWrapper>
      <ModalContent>
        <ModalHeading>{t('login_sign-in')}</ModalHeading>

        <LoginSection>
          {/* ProofPlay Wallet：浏览器装了 zchain 扩展时的原生登录入口 */}
          {typeof window !== 'undefined'
            && (window as { zchain?: { isZChain?: boolean } }).zchain?.isZChain === true && (
            <WalletButton
              type="button"
              data-testid="login-zchain"
              disabled={zchainPending}
              onClick={async () => {
                setZchainPending(true);
                try {
                  await loginWithZChain();
                } finally {
                  setZchainPending(false);
                }
              }}
            >
              <span>⛓</span>
              <span>ProofPlay Wallet</span>
            </WalletButton>
          )}
          {/* Monad 钱包：浏览器带 EIP-1193 注入 provider（MetaMask/Rabby 等）
              时的登录入口——切/加 Monad 测试网（10143）后 personal_sign 登录 */}
          {typeof window !== 'undefined' && isMonadProvider() && (
            <WalletButton
              type="button"
              data-testid="login-monad"
              disabled={monadPending}
              onClick={async () => {
                setMonadPending(true);
                try {
                  await loginWithMonad();
                } finally {
                  setMonadPending(false);
                }
              }}
            >
              <span>⬡</span>
              <span>Monad 钱包</span>
            </WalletButton>
          )}
          {availableConnectors.map((connector) => (
            <WalletButton
              key={connector.id}
              type="button"
              onClick={() => handleConnect(connector)}
              disabled={isPending}
              aria-label={`${t('login_wallet-title')} (${connector.name ?? connector.id})`}
            >
              <span className="login-btn-icon">
                <StrkLogo src={strkLogoSvg} alt="STRK" />
              </span>
              <span>
                {connector.name ?? connector.id}
                {/* Ready 是首选钱包（登录/买入/swap/私密领取均扣 Ready 余额） */}
                {/argentX|^ready$/i.test(connector.id) && ` (${t('login_recommended')})`}
              </span>
            </WalletButton>
          ))}

          {/* 未探测到任何注入钱包 → 引导安装 Ready（Chrome 插件），
              并提供"重新检测"免刷新；探测进行中不渲染任何按钮 */}
          {probed && availableConnectors.length === 0 && (
            <>
              <InstallButton
                href={READY_CHROME_STORE_URL}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span className="login-btn-icon">
                  <StrkLogo src={strkLogoSvg} alt="STRK" />
                </span>
                <span>{t('login_install-ready')}</span>
              </InstallButton>
              <RecheckButton type="button" onClick={() => setProbeTick((n) => n + 1)}>
                {t('login_recheck')}
              </RecheckButton>
            </>
          )}

          {address && (
            <WalletButton type="button" onClick={() => disconnect()}>
              <span>{t('login_disconnect')}</span>
            </WalletButton>
          )}
        </LoginSection>

        {probed && availableConnectors.length === 0 && (
          <Note>{t('login_no-wallet')}</Note>
        )}

        {error && <Note>{error.message}</Note>}
        <Note>{t('login_wallet-note')}</Note>
      </ModalContent>
    </ModalShell>,
    document.getElementById('modal') as HTMLElement,
  );
};

export default LoginModal;