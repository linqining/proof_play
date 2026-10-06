import React, { useContext, useState } from 'react';
import styled from 'styled-components';
import authContext from '../../context/auth/authContext';
import { useContentContext } from '../../context/content/contentContext';
import { useGlobalContext } from '../../context/global/globalContext';
import { chipsToStrkText } from '../../starknet/config';
import ClaimRewardsModal from '../modals/ClaimRewardsModal';

/**
 * 未领取资金横幅：登录且金库有筹码（chipsAmount > 0）时，在页面顶部
 * 常驻提醒"钱还在链上金库，不会自动回到钱包"，CTA 直接打开领取弹窗。
 *
 * 为什么用横幅而不是自动弹窗：资金提醒需要"处理前一直看得见"，弹窗
 * 会被秒关并遗忘；强打断的角色由离开牌桌时刻的内联提示承担。
 * 可关闭，但 24 小时后回归（localStorage 时间戳）。
 */

const DISMISS_KEY = 'funds_banner_dismissed_at';
const RESHOW_AFTER_MS = 24 * 60 * 60 * 1000;

const wasRecentlyDismissed = (): boolean => {
  try {
    const ts = Number(localStorage.getItem(DISMISS_KEY));
    return Number.isFinite(ts) && ts > 0 && Date.now() - ts < RESHOW_AFTER_MS;
  } catch {
    return false;
  }
};

// 宿主页面（Lobby/Home）多为居中 flex 列布局，flex 子项会 shrink-to-fit
// 被长文本撑满整行——外层 wrapper 强制自身宽度并居中，与页面内容栏对齐。
// 滚动吸附由宿主页面的槽位负责（sticky 只能在父容器范围内吸附，槽位必须
// 是页面根容器的直接子元素——Home 见 SecretPokerHomePage 的
// FundsBannerSlot；Lobby 是单屏页，流式跟随即可）。
const BannerWrap = styled.div`
  width: 100%;
  max-width: 720px;
  margin: 0 auto 1.25rem;
`;

const Banner = styled.section`
  position: relative;
  display: flex;
  align-items: center;
  gap: 0.9rem;
  padding: 0.8rem 1.1rem;
  background: linear-gradient(135deg, #fffbeb, #fef3c7);
  border: 1px solid rgba(245, 158, 11, 0.35);
  border-left: 4px solid ${({ theme }) => theme.colors.warning};
  border-radius: ${({ theme }) => theme.radius.md};

  @media screen and (max-width: 640px) {
    flex-wrap: wrap;
    gap: 0.6rem;
  }
`;

const BannerIcon = styled.span`
  flex-shrink: 0;
  display: inline-flex;
`;

const BannerText = styled.div`
  flex: 1;
  min-width: 0;

  @media screen and (max-width: 640px) {
    /* 右侧给绝对定位的关闭按钮留位 */
    padding-right: 2rem;
  }
`;

const BannerTitle = styled.p`
  margin: 0;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-weight: 600;
  font-size: 0.95rem;
  color: #78350f;

  strong {
    font-family: 'JetBrains Mono', monospace;
  }
`;

const BannerDesc = styled.p`
  margin: 0.15rem 0 0;
  font-size: 0.8rem;
  color: #92400e;
  line-height: 1.4;
`;

const ClaimCta = styled.button`
  flex-shrink: 0;
  padding: 0.55rem 1.2rem;
  border: none;
  border-radius: ${({ theme }) => theme.radius.sm};
  background: #b45309;
  color: #fff;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-weight: 600;
  font-size: ${({ theme }) => theme.fontSize.sm};
  cursor: pointer;
  transition: background-color 0.15s ease;

  &:hover {
    background: #92400e;
  }

  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px rgba(180, 83, 9, 0.4);
  }

  @media screen and (max-width: 640px) {
    width: 100%;
  }
`;

const DismissButton = styled.button`
  flex-shrink: 0;
  display: inline-flex;
  padding: 0.4rem;
  border: none;
  background: none;
  color: #b45309;
  cursor: pointer;
  border-radius: ${({ theme }) => theme.radius.xs};

  &:hover {
    background: rgba(180, 83, 9, 0.1);
  }

  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 2px rgba(180, 83, 9, 0.4);
  }

  @media screen and (max-width: 640px) {
    position: absolute;
    top: 0.45rem;
    right: 0.45rem;
  }
`;

const UnclaimedFundsBanner: React.FC = () => {
  const { isLoggedIn } = useContext(authContext)!;
  const { getLocalizedString: t } = useContentContext();
  const { chipsAmount } = useGlobalContext();
  const [dismissed, setDismissed] = useState(wasRecentlyDismissed);
  const [showClaim, setShowClaim] = useState(false);

  if (!isLoggedIn || dismissed || chipsAmount === null || chipsAmount <= 0) {
    return null;
  }

  const dismiss = () => {
    try {
      localStorage.setItem(DISMISS_KEY, String(Date.now()));
    } catch {
      // localStorage 不可用：本次会话内仍然生效（state 已置位）
    }
    setDismissed(true);
  };

  return (
    <>
      <BannerWrap>
        <Banner role="status" aria-live="polite">
        <BannerIcon aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" fill="#f59e0b" />
            <path
              d="M12 7v6m0 3h.01"
              stroke="#fff"
              strokeWidth="2.4"
              strokeLinecap="round"
            />
          </svg>
        </BannerIcon>
        <BannerText>
          <BannerTitle>
            <strong>{chipsToStrkText(chipsAmount)} STRK</strong>{' '}
            {t('funds-banner_title')}
          </BannerTitle>
          <BannerDesc>{t('funds-banner_desc')}</BannerDesc>
        </BannerText>
        <ClaimCta type="button" onClick={() => setShowClaim(true)}>
          {t('funds-banner_cta')}
        </ClaimCta>
        <DismissButton type="button" onClick={dismiss} aria-label={t('funds-banner_dismiss')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M6 6l12 12M18 6L6 18"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
            />
          </svg>
        </DismissButton>
        </Banner>
      </BannerWrap>
      {showClaim && (
        <ClaimRewardsModal
          isOpen={showClaim}
          chipsAmount={chipsAmount}
          onClose={() => setShowClaim(false)}
        />
      )}
    </>
  );
};

export default UnclaimedFundsBanner;
