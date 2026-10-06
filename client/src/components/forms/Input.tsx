import styled from 'styled-components';

export const Input = styled.input`
  /* 44px 触控目标（Apple HIG）；移动端布局按此基线设计 */
  height: 44px;
  overflow: hidden;
  padding: 0.5rem 1rem;
  text-align: left;
  font-size: 1.1rem;
  border: none;
  border-radius: calc(
    ${({ theme }) => theme.other.stdBorderRadius} - 1.25rem
  );
  background-color: ${({ theme }) => theme.colors.playingCardBgLighter};
  color: ${({ theme }) => theme.colors.primaryCta};
  width: 100%;

  &:focus {
    outline: none;
    border: 1px solid ${({ theme }) => theme.colors.primaryCta};
  }
`;
