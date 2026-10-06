import React from 'react';
import styled from 'styled-components';
import strkLogoSvg from '/strk-logo.svg';

/**
 * 钱包胶囊：余额段（只读）+ Claim 段（打开领取弹窗），一颗胶囊两段式。
 * 替代旧的余额/领取两个散落 pill——统一高度/圆角/字号，颜色走 theme token。
 */

interface WalletPillProps {
  /** 格式化后的余额（如 "12.34"）；null = 加载中，显示 "—" 而非误导性的 0 */
  balance: string | null;
  /** 悬浮提示：换算后的完整 STRK 数值（而非 wei 原始值） */
  balanceTitle: string;
  logoAlt: string;
  claimLabel: string;
  claimTitle: string;
  onClaim: () => void;
  /** 有可领奖励时亮绿点（可领状态查询后续接入，先留视觉位） */
  hasClaimable?: boolean;
}

// theme 无 info 的 alpha token，余额段蓝色系在组件内用命名常量统一
// 账簿：余额数字用墨色等宽（原蓝色 play 强调降级）
const INFO_RGB = '20, 19, 15';

const PillWrapper = styled.div`
  display: inline-flex;
  align-items: stretch;
  height: 40px;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
  overflow: hidden;
`;

const BalanceSegment = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0 0.75rem;
  color: rgb(${INFO_RGB});
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-weight: 600;
  font-size: ${({ theme }) => theme.fontSize.sm};
  white-space: nowrap;

  img {
    width: 16px;
    height: 16px;
    flex-shrink: 0;
  }
`;

const Divider = styled.span`
  width: 1px;
  background: ${({ theme }) => theme.colors.borderSubtle};
`;

const ClaimSegment = styled.button`
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0 0.85rem;
  border: none;
  background: ${({ theme }) => theme.colors.successAlpha12};
  color: ${({ theme }) => theme.colors.successStrong};
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-weight: 600;
  font-size: ${({ theme }) => theme.fontSize.sm};
  cursor: pointer;
  white-space: nowrap;
  transition: background-color 0.15s ease;

  &:hover {
    background: ${({ theme }) => theme.colors.successAlpha20};
  }

  &:focus-visible {
    outline: none;
    box-shadow: inset 0 0 0 2px ${({ theme }) => theme.colors.successAlpha20};
  }
`;

const ClaimDot = styled.span`
  position: absolute;
  top: 6px;
  right: 6px;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: ${({ theme }) => theme.colors.success};
  box-shadow: 0 0 0 2px ${({ theme }) => theme.colors.lightestBg};
`;

const ClaimIcon = () => (
  <svg
    width="14"
    height="14"
    viewBox="0 0 24 24"
    fill="none"
    aria-hidden="true"
    style={{ flexShrink: 0 }}
  >
    <path
      d="M12 4v13m0 0l-6-6m6 6l6-6"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

const WalletPill: React.FC<WalletPillProps> = ({
  balance,
  balanceTitle,
  logoAlt,
  claimLabel,
  claimTitle,
  onClaim,
  hasClaimable = false,
}) => (
  <PillWrapper>
    <BalanceSegment title={balanceTitle} aria-label={balanceTitle}>
      <img src={strkLogoSvg} alt={logoAlt} />
      <span>{balance ?? '—'}</span>
      <span className="pill-strk-suffix">STRK</span>
    </BalanceSegment>
    <Divider aria-hidden="true" />
    <ClaimSegment type="button" onClick={onClaim} title={claimTitle} aria-label={claimTitle}>
      <ClaimIcon />
      <span>{claimLabel}</span>
      {hasClaimable && <ClaimDot />}
    </ClaimSegment>
  </PillWrapper>
);

export default WalletPill;
