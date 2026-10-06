import React, { useContext, useEffect, useRef } from 'react';
import styled from 'styled-components';
import CloseButton from '../buttons/CloseButton';
import Button from '../buttons/Button';
import Text from '../typography/Text';
import ColoredText from '../typography/ColoredText';
import { PlayerName } from '../game/PlayerName';
import ChipsAmount from '../user/ChipsAmount';
import { Link } from 'react-router-dom';
import lobbyIcon from '../../assets/icons/lobby-icon.svg';
import userIcon from '../../assets/icons/user-icon.svg';
import contentContext from '../../context/content/contentContext';
import globalContext from '../../context/global/globalContext';
import LanguageSwitcher from './LanguageSwitcher';
import PlayerKeyPanel from './PlayerKeyPanel';
import { fontMono } from '../../styles/theme';

const NavMenuWrapper = styled.div`
  position: fixed;
  display: flex;
  justify-content: center;
  align-items: center;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: ${({ theme }) => theme.zIndex.drawer};
  /* 账簿遮罩：纯色暗纱，零毛玻璃 */
  background-color: rgba(20, 19, 15, 0.42);
  overscroll-behavior: contain;
`;

const StyledNavMenu = styled.div`
  position: fixed;
  display: flex;
  flex-direction: column;
  top: 0;
  right: 0;
  width: 320px;
  height: 100%;
  /* 账簿：卡白实底 + 细线桌沿，零半透明零光晕 */
  background: ${({ theme }) => theme.colors.lightestBg};
  border-left: 1px solid ${({ theme }) => theme.colors.borderMuted};
  box-shadow: -6px 0 24px rgba(20, 19, 15, 0.1);
  overflow: hidden;

  @media screen and (max-width: 400px) {
    width: 85vw;
  }
`;

const MenuHeader = styled.div`
  padding: 1rem 1.25rem 0;
  justify-self: flex-start;
`;

const MenuItem = styled(Link)`
  display: flex;
  padding: 0.85rem 1.25rem;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  text-align: right;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  color: ${({ theme }) => theme.colors.fontColorDark} !important;
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  background-color: transparent !important;
  border-left: 3px solid transparent;
  font-size: 0.95rem;
  font-weight: 500;
  text-decoration: none;
  transition:
    background-color 0.2s ease,
    color 0.2s ease,
    border-left-color 0.2s ease;

  img {
    opacity: 0.6;
    transition: opacity 0.2s ease;
  }

  &:hover {
    background-color: ${({ theme }) => theme.colors.successAlpha12} !important;
    border-left-color: ${({ theme }) => theme.colors.success};
    color: ${({ theme }) => theme.colors.fontColorDark} !important;

    img {
      opacity: 1;
    }
  }

  &:focus {
    outline: none;
    border-left: 3px solid ${({ theme }) => theme.colors.success};
  }
`;

const MenuBody = styled.div`
  overflow-y: auto;
  overscroll-behavior: contain;
  margin-top: 0.5rem;

  &::-webkit-scrollbar {
    width: 0.4rem;
  }

  &::-webkit-scrollbar-track {
    background: transparent;
  }

  &::-webkit-scrollbar-thumb {
    background: ${({ theme }) => theme.colors.borderMuted};
    border-radius: 2px;
  }
`;

const MenuFooter = styled.div`
  padding: 1rem 1.25rem;
  margin: auto 0 0 0;
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
`;

/* Single source of truth for nav menu icon dimensions. The audit (P1-47)
   flagged that the prior version set both HTML width="22" AND an inline
   `style={{ width: '22px' }}` for every menu icon — the inline style won
   but duplicated the literal. Centralize here. */
const MenuIcon = styled.img`
  width: 22px;
  height: 22px;
  flex-shrink: 0;
`;

const HorizontalWrapper = styled.div`
  display: flex;
  margin: 1.5rem auto;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;

  ${Button} {
    min-width: 6.5rem;
    background: ${({ theme }) => theme.colors.primaryCta} !important;
    color: #fffdf7 !important;
    border: none !important;
    border-radius: ${({ theme }) => theme.radius.sm} !important;
    box-shadow: none !important;
  }
`;

const SalutationText = styled(Text)`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 1.25rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: -0.02em;

  /* 账簿：问候地址 = felt 实色（原蓝紫渐变文字废除） */
  ${ColoredText} {
    color: ${({ theme }) => theme.colors.success};
  }
`;

const OnlineText = styled(Text)`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.softerText};
  margin-top: 0.25rem;

  ${ColoredText} {
    color: ${({ theme }) => theme.colors.success};
    font-weight: 600;
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
  }
`;

const IconWrapper = styled.div`
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;

  button {
    color: ${({ theme }) => theme.colors.softerText} !important;

    &:hover {
      color: ${({ theme }) => theme.colors.fontColorDark} !important;
    }
  }
`;

/* 退出登录：账簿描边钮（非主操作） */
const LogoutButton = styled.button`
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: ${({ theme }) => theme.radius.sm};
  background: transparent;
  color: ${({ theme }) => theme.colors.danger};
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition:
    background-color 0.15s ease,
    border-color 0.15s ease;

  &:hover {
    background: ${({ theme }) => theme.colors.dangerAlpha06};
    border-color: ${({ theme }) => theme.colors.danger};
  }
`;

/* 账簿注记行（原稿 .wm 语言） */
const MicroFoot = styled.div`
  margin-top: 0.6rem;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 8px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
  opacity: 0.7;
  text-align: center;
`;

interface NavMenuProps {
  onClose: () => void;
  userName: string | null;
  chipsAmount: number | null;
  lang?: string;
  setLang?: React.Dispatch<React.SetStateAction<string>>;
  openModal: (
    children: () => React.ReactNode,
    headingText: string,
    btnText: string,
    btnCallBack?: () => void,
    onCloseCallBack?: () => void,
  ) => void;
  /** 登出（MainLayout 传入：清 socket + 断钱包 + 清登录态） */
  onLogout?: () => void;
  loggedIn?: boolean;
}

const NavMenu: React.FC<NavMenuProps> = ({
  onClose,
  userName,
  chipsAmount,
  openModal,
  onLogout,
  loggedIn,
}) => {
  const { players } = useContext(globalContext)!;
  const { getLocalizedString } = useContext(contentContext)!;
  const menuRef = useRef<HTMLDivElement>(null);

  // 抽屉是对话框：Esc 关闭、打开期间锁定 body 滚动、关闭后焦点还原
  useEffect(() => {
    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const savedOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = savedOverflow;
      previouslyFocused?.focus();
    };
  }, [onClose]);

  // Tab 循环限制在抽屉内
  const onTabKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'Tab') return;
    const menu = menuRef.current;
    if (!menu) return;
    const items = Array.from(
      menu.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((el) => el.offsetParent !== null);
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  const openShopModal = () =>
    openModal(
      () => (
        <Text textAlign="center">
            {getLocalizedString('shop-coming_soon-modal_text')}
          </Text>
      ),
      getLocalizedString('shop-coming_soon-modal_heading'),
      getLocalizedString('shop-coming_soon-modal_btn_text'),
    );

  return (
    <NavMenuWrapper
      id="wrapper"
      onClick={(e) => {
        if ((e.target as HTMLElement).id === 'wrapper') {
          onClose();
        }
      }}
    >
      <StyledNavMenu
        ref={menuRef}
        role="dialog"
        aria-modal="true"
        aria-label={getLocalizedString('navmenu-aria_label')}
        onKeyDown={onTabKeyDown}
      >
        <IconWrapper>
          <CloseButton clickHandler={onClose} autoFocus />
        </IconWrapper>
        <MenuHeader>
          <SalutationText textAlign="left">
            {getLocalizedString('main_page-salutation')}
            <br />
            <ColoredText><PlayerName name={userName ?? getLocalizedString('main_page-guest-name')} />!</ColoredText>
          </SalutationText>
          {players && (
            <OnlineText textAlign="left">
              {getLocalizedString('game_online-lbl')} <ColoredText>{players.length}</ColoredText>
            </OnlineText>
          )}
          <HorizontalWrapper>
            <ChipsAmount
              chipsAmount={chipsAmount ?? 0}
              clickHandler={openShopModal}
            />
            <Button onClick={openShopModal} small primary>
              {getLocalizedString('shop-coming_soon-modal_heading')}
            </Button>
          </HorizontalWrapper>
        </MenuHeader>
        <MenuBody>
          <MenuItem
            to="/"
            onClick={() => {
              onClose();
            }}
          >
            {getLocalizedString('navmenu-menu_item-lobby_txt')}
            <MenuIcon
              src={lobbyIcon}
              alt={getLocalizedString('navbar_lobby-alt')}
            />
          </MenuItem>
          <MenuItem
            to="/dashboard"
            onClick={() => {
              onClose();
            }}
          >
            {getLocalizedString('navmenu-menu_item-dashboard_txt')}
            <MenuIcon
              src={userIcon}
              alt={getLocalizedString('navbar_dashboard-alt')}
            />
          </MenuItem>

        </MenuBody>
        <PlayerKeyPanel />
        <MenuFooter>
          <LanguageSwitcher />
          {loggedIn && onLogout && (
            <LogoutButton
              type="button"
              style={{ marginTop: '0.75rem' }}
              onClick={() => {
                onClose();
                onLogout();
              }}
            >
              {getLocalizedString('navmenu-logout')}
            </LogoutButton>
          )}
          <MicroFoot>zchain · appchain texas</MicroFoot>
        </MenuFooter>
      </StyledNavMenu>
    </NavMenuWrapper>
  );
};

export default NavMenu;
