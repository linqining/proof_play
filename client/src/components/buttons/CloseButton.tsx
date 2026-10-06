import React from 'react';
import styled from 'styled-components';
import CloseIcon from '../icons/CloseIcon';

const StyledCloseButton = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  padding: ${({ theme }) => theme.other.safeAreaTop};
  min-width: 44px;
  min-height: 44px;
  cursor: pointer;
  color: ${({ theme }) => theme.colors.softText};
  border-radius: ${({ theme }) => theme.radius.pill};
  transition:
    color ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard},
    background-color ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard};

  &:hover:not(:disabled) {
    color: ${({ theme }) => theme.colors.fontColorDark};
    background-color: ${({ theme }) => theme.colors.surfaceMuted};
  }

  &:focus-visible {
    outline: 2px solid ${({ theme }) => theme.colors.primaryCta};
    outline-offset: 2px;
  }
`;

interface CloseButtonProps {
  clickHandler: () => void;
  autoFocus?: boolean;
  ariaLabel?: string;
}

const CloseButton: React.FC<CloseButtonProps> = ({ clickHandler, autoFocus, ariaLabel = 'Close' }) => {
  return (
    <StyledCloseButton
      type="button"
      onClick={clickHandler}
      autoFocus={autoFocus}
      aria-label={ariaLabel}
    >
      <CloseIcon />
    </StyledCloseButton>
  );
};

export default CloseButton;
