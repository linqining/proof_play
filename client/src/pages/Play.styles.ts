import styled from 'styled-components';

// 离开牌桌时的全屏遮罩
export const LeavingOverlay = styled.div`
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.7);
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  z-index: ${({ theme }) => theme.zIndex.critical};
`;

// 玩家操作签名中的全屏遮罩
export const ActionLoadingOverlay = styled.div`
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.6);
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  z-index: ${({ theme }) => theme.zIndex.loading};
  pointer-events: auto;
`;

// 等待牌局结束后离开的横幅（Task 8）
// 浮动在牌桌顶部，使用 warning 配色以提示用户当前处于 deferred 状态
export const LeaveDeferredBanner = styled.div`
  position: absolute;
  top: 1rem;
  left: 50%;
  transform: translateX(-50%);
  z-index: ${({ theme }) => theme.zIndex.overlay};
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 1rem;
  background: ${({ theme }) => theme.colors.warning};
  color: ${({ theme }) => theme.colors.fontColorDark};
  border-radius: ${({ theme }) => theme.radius.pill};
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: ${({ theme }) => theme.fontSize.sm};
  font-weight: 600;
  max-width: calc(100% - 2rem);
  pointer-events: auto;
`;
