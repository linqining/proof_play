import styled from 'styled-components';

export const Select = styled.select`
  /* 44px 触控目标（Apple HIG） */
  height: 44px;
  overflow: hidden;
  padding: 0 0.5rem;
  text-align: right;
  font-size: 1.1rem;
  border: none;
  border-radius: calc(
    ${({ theme }) => theme.other.stdBorderRadius} - 1.25rem
  );
  background-color: ${({ theme }) => theme.colors.playingCardBgLighter};
  border-color: ${({ theme }) => theme.colors.secondaryCta};
  color: ${({ theme }) => theme.colors.primaryCta};
  width: 100%;

  &:focus {
    outline: none;
    /* box-shadow 替代加粗 border，避免聚焦时布局抖动 */
    outline: 2px solid ${({ theme }) => theme.colors.primaryCta};
    outline-offset: -2px;
  }
`;
