import React from 'react';
import HamburgerIcon from '../icons/HamburgerIcon';
import styled from 'styled-components';

const StyledHamburgerButton = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  padding: 0.5rem;
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

interface HamburgerButtonProps {
  clickHandler: () => void;
  ariaLabel?: string;
}

const HamburgerButton: React.FC<HamburgerButtonProps> = ({ clickHandler, ariaLabel = 'Open menu' }) => {
  return (
    <StyledHamburgerButton type="button" onClick={clickHandler} aria-label={ariaLabel}>
      <HamburgerIcon />
    </StyledHamburgerButton>
  );
};

export default HamburgerButton;
