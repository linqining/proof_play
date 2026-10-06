import styled, { css } from 'styled-components';

interface HiderProps {
  hideOnDesktop?: boolean;
  hideOnMobile?: boolean;
}

const Hider = styled.div.withConfig({
  shouldForwardProp: (prop) => !['hideOnDesktop', 'hideOnMobile'].includes(prop),
})<HiderProps>`
  display: none;

  ${({ hideOnMobile }) =>
    hideOnMobile &&
    css`
      display: initial;

      @media screen and (max-width: 1024px) {
        display: none;
      }
    `}

  ${({ hideOnDesktop }) =>
    hideOnDesktop &&
    css`
      @media screen and (max-width: 1024px) {
        display: flex;
      }
    `}
`;

export default Hider;
