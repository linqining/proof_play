import React, { useContext, useState } from 'react';
import styled from 'styled-components';
import LogoWithText from '../logo/LogoWithText';
import Logo from '../logo/LogoIcon';
import Container from '../layout/Container';
import { Link, useNavigate } from 'react-router-dom';
import Hider from '../layout/Hider';
import Button from '../buttons/Button';
import HamburgerButton from '../buttons/HamburgerButton';
import Spacer from '../layout/Spacer';
import contentContext from '../../context/content/contentContext';
import authContext from '../../context/auth/authContext';
import { useGlobalContext } from '../../context/global/globalContext';
import { STRK_DECIMALS } from '../../starknet/config';
import ClaimRewardsModal from '../modals/ClaimRewardsModal';
import WalletPill from './WalletPill';
import AccountMenu from './AccountMenu';

interface NavbarProps {
  loggedIn: boolean;
  chipsAmount: number | null;
  openNavMenu: () => void;
  onSignIn?: () => void;
  onLogout?: () => void;
  className?: string;
  variant?: 'light' | 'dark';
}

const StyledNav = styled.nav`
  padding: 1rem 0;
  /* 吸顶：文档级 scroll-snap 在窗口宽度变化后会重新吸附（产生几十 px 的
     滚动），absolute 定位的导航栏会跟着滚出视口上沿——logo 被切半、原位
     置露出一条白带，看起来像整页排版坏了（2026-09-06 线上截图复现）。
     fixed 让导航栏始终盖住视口顶部，微小的重吸附滚动不再可见。 */
  position: fixed;
  top: 0;
  left: 0;
  z-index: ${({ theme }) => theme.zIndex.nav};
  width: 100%;
  /* 高度与 theme.other.navHeight 保持一致——页面顶部避让和 scroll
     padding 都引用该令牌，改这里要同步改令牌。 */
  min-height: ${({ theme }) => theme.other.navHeight};
  box-sizing: border-box;
  transition: background-color 0.4s ease;
  background-color: ${({ theme }) => theme.colors.lightestBg};
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
`;

const StyledHamburgerButton = styled(HamburgerButton)`
  .hamburger-line {
    background-color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

// 账簿还原（design/client C6）：主操作 = felt 实底方角，零渐变零浮起
const LoginButton = styled(Button)`
  background: ${({ theme }) => theme.colors.primaryCta};
  color: #fffdf7;
  border: none;
  border-radius: ${({ theme }) => theme.radius.sm};
  box-shadow: none;
  &:hover {
    transform: none;
    background: ${({ theme }) => theme.colors.primaryCtaDarker};
    box-shadow: none;
  }
`;

/** bigint wei → STRK 十进制字符串；maxFrac 控制小数位（展示 4 位，tooltip 全精度） */
const formatStrk = (raw: bigint, maxFrac: number): string => {
  const scale = BigInt(10) ** BigInt(STRK_DECIMALS);
  const whole = raw / scale;
  const frac = (raw % scale)
    .toString()
    .padStart(STRK_DECIMALS, '0')
    .slice(0, maxFrac)
    .replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
};

const Navbar: React.FC<NavbarProps> = ({
  loggedIn,
  chipsAmount,
  openNavMenu,
  onSignIn,
  onLogout,
  className,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const { walletAddress } = useContext(authContext)!;
  const { strkBalance } = useGlobalContext();
  const navigate = useNavigate();
  const [showClaim, setShowClaim] = useState(false);

  // 余额统一由 useAuth 拉取并写入全局 strkBalance（此前 Navbar 重复拉过一次）
  const strkDisplay = strkBalance === null ? null : formatStrk(strkBalance, 4);
  const strkFull = strkBalance === null ? '' : formatStrk(strkBalance, STRK_DECIMALS);
  const balanceLabel = getLocalizedString('seat_strk-balance-label');
  const balanceTitle =
    strkBalance === null ? balanceLabel : `${balanceLabel}: ${strkFull} STRK`;

  const handleSignIn = () => {
    if (onSignIn) {
      onSignIn();
    } else {
      navigate('/');
    }
  };

  if (!loggedIn) {
    return (
      <StyledNav className={className}>
        <Container contentCenteredMobile>
          <Link to="/">
            <LogoWithText />
          </Link>
          <Spacer>
            <LoginButton onClick={handleSignIn}>
              {getLocalizedString('navbar-signin_btn')}
            </LoginButton>
          </Spacer>
        </Container>
      </StyledNav>
    );
  }

  return (
    <StyledNav className={className}>
      <Container>
        <Link to="/">
          <Hider hideOnMobile>
            <LogoWithText />
          </Hider>
          <Hider hideOnDesktop>
            <Logo />
          </Hider>
        </Link>
        <Spacer>
          <WalletPill
            balance={strkDisplay}
            balanceTitle={balanceTitle}
            logoAlt={getLocalizedString('seat_strk-logo-alt')}
            claimLabel={getLocalizedString('navbar-claim_btn')}
            claimTitle={getLocalizedString('navbar-claim_tip')}
            hasClaimable={(chipsAmount ?? 0) > 0}
            onClaim={() => setShowClaim(true)}
          />
          {walletAddress && (
            <AccountMenu
              address={walletAddress}
              copyLabel={getLocalizedString('navbar-copy-address')}
              copiedLabel={getLocalizedString('navbar-copied')}
              logoutLabel={getLocalizedString('navmenu-logout_btn')}
              onLogout={onLogout}
            />
          )}
          <StyledHamburgerButton clickHandler={openNavMenu} />
        </Spacer>
      </Container>
      {showClaim && (
        <ClaimRewardsModal
          isOpen={showClaim}
          chipsAmount={chipsAmount}
          onClose={() => setShowClaim(false)}
        />
      )}
    </StyledNav>
  );
};

export default Navbar;
