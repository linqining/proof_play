import styled from 'styled-components';
import { responsiveScale } from './responsiveScale';

/**
 * 行动区容器（GameUI 底部页脚）：账簿纸面（设计稿 .tb-ft 语义）。
 */
export const UIWrapper = styled.div`
  position: fixed;
  bottom: calc(1vh + env(safe-area-inset-bottom, 0px));
  right: calc(1vh + env(safe-area-inset-right, 0px));
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  grid-gap: 0.5rem;
  background-color: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.fontColorDark};
  box-shadow: 0 6px 24px rgba(20, 19, 15, 0.14);
  border-radius: ${({ theme }) => theme.other.stdBorderRadius};
  padding: 1rem;
  transform-origin: bottom right;
  -webkit-backface-visibility: hidden;
  backface-visibility: hidden;
  /* Avoid overscroll chaining from the floating HUD into the page */
  overscroll-behavior: contain;
  max-width: min(92vw, 720px);

  ${responsiveScale(0.5)}

  /* Hide on narrow portrait phones: the chip tray is the primary
     in-game control and the HUD would steal touch real-estate. */
  @media screen and (max-width: 479px) and (orientation: portrait) {
    display: none;
  }
`;
