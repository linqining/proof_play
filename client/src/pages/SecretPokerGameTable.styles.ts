import styled from 'styled-components';

/* ===== 共享：居中提示容器（loading / not found） ===== */

export const CenteredMessageContainer = styled.div`
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1rem;
  background: ${({ theme }) => theme.colors.fontColorLight};
  color: ${({ theme }) => theme.colors.mutedText};
`;

/* ===== 共享：渐变按钮（Back to Lobby / 抽屉开关） ===== */

export const GradientButton = styled.button`
  background: ${({ theme }) => theme.colors.brandGradient};
  color: ${({ theme }) => theme.colors.lightestBg};
  border: none;
  padding: 0.65rem 1.6rem;
  border-radius: ${({ theme }) => theme.radius.md};
  font-weight: 600;
  cursor: pointer;
`;

/* ===== 主容器 ===== */

export const MainContainer = styled.div`
  /* Expose z-index + surface color values as CSS custom properties so the
     inlined <style> block in SecretPokerGameTable.tsx (which needs media
     query breakpoints inside a single className) can reference them
     without losing the theme binding. */
  --zk-drawer-z: ${({ theme }) => theme.zIndex.drawer};
  --zk-overlay-z: ${({ theme }) => theme.zIndex.overlay};
  --zk-panel-bg: ${({ theme }) => theme.colors.lightestBg};
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  background: ${({ theme }) => theme.colors.fontColorLight};
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

/* ===== 顶部状态栏 ===== */

export const TopBar = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem 2rem;
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderMuted};
  margin-top: 60px; /* Account for global Navbar */
`;

/* 共享：次要操作按钮（Lobby / Refresh） */
export const SecondaryActionButton = styled.button`
  background: ${({ theme }) => theme.colors.surfaceMuted};
  color: ${({ theme }) => theme.colors.fontColorDark};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  padding: 0.4rem 0.8rem;
  border-radius: ${({ theme }) => theme.radius.sm};
  font-weight: 500;
  font-size: 0.82rem;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
`;

export const TopBarCenter = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
`;

export const PhaseBadge = styled.span`
  padding: 0.3rem 0.8rem;
  border-radius: ${({ theme }) => theme.radius.sm};
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  background: rgba(59, 130, 246, 0.15);
  color: ${({ theme }) => theme.colors.info};
`;

export const PotDisplay = styled.span`
  color: ${({ theme }) => theme.colors.gold};
  font-weight: 700;
`;

export const TopBarRight = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

/* 抽屉开关按钮（窄屏可见，宽屏由 CSS 隐藏） */
export const DrawerToggleButton = styled(GradientButton)`
  padding: 0.4rem 0.8rem;
  border-radius: ${({ theme }) => theme.radius.sm};
  font-size: 0.82rem;
  align-items: center;
  gap: 0.3rem;
`;

/* ===== 主体布局 ===== */

export const MainLayout = styled.div`
  flex: 1;
  padding: 2rem;
`;

/* ===== 牌桌卡片 ===== */

export const TableCard = styled.div`
  width: 100%;
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.other.stdBorderRadius};
  padding: 2rem;
`;

export const GameTitle = styled.h2`
  text-align: center;
  margin-bottom: 1.5rem;
  font-family: 'Inter', sans-serif;
`;

/* ===== 玩家 ===== */

export const PlayersGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
`;

export const PlayerSeat = styled.div<{ $active: boolean }>`
  background: rgba(226, 232, 240, 0.5);
  border-radius: ${({ theme }) => theme.radius.md};
  padding: 1rem;
  text-align: center;
  border: ${({ $active, theme }) =>
    $active
      ? `2px solid ${theme.colors.success}`
      : `1px solid ${theme.colors.borderSubtle}`};
`;

export const PlayerNameDisplay = styled.div<{ $folded: boolean }>`
  font-weight: 600;
  margin-bottom: 0.3rem;
  text-decoration: ${({ $folded }) => ($folded ? 'line-through' : 'none')};
  opacity: ${({ $folded }) => ($folded ? 0.4 : 1)};
`;

export const PlayerChips = styled.div`
  color: ${({ theme }) => theme.colors.gold};
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
`;

export const PlayerBet = styled.div`
  color: ${({ theme }) => theme.colors.warning};
  font-size: 0.8rem;
  margin-top: 0.3rem;
`;

/* ===== 公共牌 ===== */

export const CommunityCardsSection = styled.div`
  text-align: center;
  margin-bottom: 1.5rem;
`;

/* 共享：小节标签（Community Cards / 密码学事件流 / 选中事件详情） */
export const SectionLabel = styled.div`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.softText};
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 0.5rem;
`;

export const SectionLabelTight = styled(SectionLabel)`
  letter-spacing: 0.06em;
  margin-bottom: 0.4rem;
  font-weight: 600;
`;

export const SectionLabelDetail = styled(SectionLabelTight)`
  margin-bottom: 0.5rem;
`;

export const CardsRow = styled.div`
  display: flex;
  gap: 0.5rem;
  justify-content: center;
`;

export const CardDisplay = styled.div<{ $revealed: boolean; $isRed: boolean }>`
  width: 50px;
  height: 70px;
  border-radius: 8px;
  background: ${({ $revealed }) =>
    $revealed
      ? 'linear-gradient(145deg, #ffffff, #f0f0f0)'
      : 'linear-gradient(145deg, #1a3050, #0d1f35)'};
  border: ${({ $revealed }) =>
    $revealed
      ? '1px solid rgba(0,0,0,0.08)'
      : '2px solid #2a4a70'};
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: ${({ $revealed }) => ($revealed ? '0.9rem' : '1.4rem')};
  font-weight: 700;
  color: ${({ $revealed, $isRed }) =>
    $revealed
      ? ($isRed ? '#dc2626' : '#1a1a1a')
      : 'rgba(255,255,255,0.15)'};
  box-shadow: 0 3px 12px rgba(0, 0, 0, 0.08);
`;

/* ===== 赢家横幅 ===== */

export const WinnerBanner = styled.div`
  background: linear-gradient(135deg, rgba(212, 175, 55, 0.12), rgba(245, 158, 11, 0.12));
  border: 1px solid rgba(212, 175, 55, 0.35);
  color: ${({ theme }) => theme.colors.warningDark};
  padding: 0.8rem 1.2rem;
  border-radius: ${({ theme }) => theme.radius.sm};
  font-weight: 700;
  text-align: center;
  font-size: 1.05rem;
  margin-bottom: 1rem;
`;

/* ===== ZK 可视化面板 ===== */

export const ZkPanel = styled.div`
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.lg};
`;

export const PanelInner = styled.div`
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

export const PanelHeader = styled.div`
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 0.5rem;
`;

export const PanelTitle = styled.h3`
  margin: 0;
  font-size: 1.05rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

export const PanelSubtitle = styled.p`
  margin: 0.2rem 0 0;
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.softText};
`;

/* 面板关闭按钮（窄屏可见，图标按钮） */
export const PanelCloseButton = styled.button`
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: ${({ theme }) => theme.radius.sm};
  padding: 0.3rem;
  cursor: pointer;
  color: ${({ theme }) => theme.colors.mutedText};
  align-items: center;
  justify-content: center;
`;

export const EventStreamContainer = styled.div`
  height: 300px;
`;

export const EventDetailColumn = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

export const EventTypeRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
`;

export const EventTypeLabel = styled.span`
  font-weight: 700;
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: 0.04em;
`;

export const RevealTokenCards = styled.div`
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  justify-content: center;
  padding: 0.75rem 0.5rem;
  background: rgba(248, 250, 252, 0.6);
  border-radius: ${({ theme }) => theme.radius.md};
`;

export const EventMessage = styled.div`
  font-size: 0.8rem;
  color: ${({ theme }) => theme.colors.mutedText};
  background: rgba(248, 250, 252, 0.8);
  border-radius: ${({ theme }) => theme.radius.sm};
  padding: 0.6rem 0.8rem;
`;

export const EmptyDetailPlaceholder = styled.div`
  padding: 1.2rem 0.5rem;
  text-align: center;
  color: ${({ theme }) => theme.colors.softerText};
  font-style: italic;
  font-size: 0.85rem;
  background: rgba(248, 250, 252, 0.6);
  border-radius: ${({ theme }) => theme.radius.sm};
`;

/* ===== 原始日志 ===== */

export const RawLogSection = styled.div`
  background: ${({ theme }) => theme.colors.surfaceSubtle};
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  padding: 0.75rem 2rem;
`;

export const RawLogToggleButton = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  background: none;
  border: none;
  cursor: pointer;
  font-size: 0.82rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.mutedText};
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 0;
`;

export const RawLogContent = styled.div`
  max-height: 200px;
  overflow-y: auto;
  overscroll-behavior: contain;
  margin-top: 0.75rem;
  font-size: 0.78rem;
  font-family: 'JetBrains Mono', monospace;
`;

export const EmptyLog = styled.div`
  color: ${({ theme }) => theme.colors.softText};
  font-style: italic;
  text-align: center;
  padding: 1rem 0;
`;

export const LogEntry = styled.div`
  padding: 0.25rem 0;
  color: ${({ theme }) => theme.colors.softText};
  border-bottom: 1px solid rgba(0, 0, 0, 0.05);
`;

/* ===== 错误提示 toast ===== */

/* button 而非 div onClick：键盘可关闭（WCAG 2.1.1） */
export const ErrorToast = styled.button`
  position: fixed;
  bottom: 2rem;
  right: 2rem;
  background: ${({ theme }) => theme.colors.dangerAlpha95};
  color: ${({ theme }) => theme.colors.lightestBg};
  border: none;
  font-family: inherit;
  padding: 0.8rem 1.5rem;
  border-radius: ${({ theme }) => theme.radius.sm};
  font-size: 0.9rem;
  z-index: ${({ theme }) => theme.zIndex.toast};
  cursor: pointer;
  text-align: left;
`;

/* ===== Layout primitives (formerly inlined in <style> tag) ===== */

export const ZkLayout = styled.div`
  display: flex;
  flex-direction: row;
  gap: 1.5rem;
`;

export const ZkLeft = styled.div`
  flex: 0 0 60%;
  min-width: 0;
`;

export const ZkPanelArea = styled.div`
  position: relative;
  flex: 0 0 40%;
  min-width: 0;
`;

export const ZkPanelDrawer = styled.div<{ $open: boolean }>`
  background: ${({ theme }) => theme.colors.lightestBg};
  transition: transform ${({ theme }) => theme.timing.base} ease;
  overflow-y: auto;
  overscroll-behavior: contain;
  flex: none;

  @media screen and (min-width: 1024px) {
    position: relative;
  }

  @media screen and (max-width: 1023px) {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: 380px;
    max-width: 85vw;
    z-index: ${({ theme }) => theme.zIndex.drawer};
    box-shadow: -8px 0 24px rgba(0, 0, 0, 0.15);
    transform: translateX(${({ $open }) => ($open ? '0' : '100%')});
  }
`;

export const ZkDrawerButton = styled.button`
  display: none;
  @media screen and (max-width: 1023px) {
    display: inline-flex;
  }
`;

export const ZkPanelClose = styled.button`
  display: none;
  @media screen and (max-width: 1023px) {
    display: inline-flex;
  }
`;

export const ZkBackdrop = styled.div`
  display: none;
  @media screen and (max-width: 1023px) {
    display: block;
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.3);
    z-index: ${({ theme }) => theme.zIndex.overlay};
  }
`;
