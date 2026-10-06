import React from 'react';
import EyeIcon from '../icons/EyeIcon';
import styled from 'styled-components';

/* ShowPasswordButton is a clickable affordance next to a password input.
   Audit P1-45: the prior version had a 30px wide SVG with no padding,
   which made the touch target smaller than the Apple HIG 44x44 minimum
   on mobile. We now expose a 44x44 button-shaped container and let the
   icon size itself within it.
   Audit P1-50: prior version used a <div> onClick which is not
   keyboard-focusable. Using a <button> with a meaningful aria-label
   fixes that. */
const StyledShowPasswordButton = styled.button`
  position: absolute;
  z-index: 40;
  right: 4px;
  bottom: 2px;
  width: 44px;
  height: 44px;
  padding: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  background: transparent;
  border: none;
  border-radius: ${({ theme }) => theme.radius.xs};
  color: ${({ theme }) => theme.colors.mutedText};
  transition: color 0.2s ease, background 0.2s ease;

  &:hover {
    color: ${({ theme }) => theme.colors.secondaryCta};
    background: ${({ theme }) => theme.colors.surfaceMuted};
  }

  &:focus-visible {
    outline: 2px solid ${({ theme }) => theme.colors.brandPurple};
    outline-offset: 2px;
  }

  svg {
    width: 20px;
    height: 20px;
  }
`;

const togglePasswordVisibility = (ref: React.RefObject<HTMLInputElement | null>) => {
  if (ref.current?.type === 'password') {
    ref.current.type = 'text';
  } else if (ref.current) {
    ref.current.type = 'password';
  }
};

interface ShowPasswordButtonProps {
  passwordRef: React.RefObject<HTMLInputElement | null>;
}

const ShowPasswordButton: React.FC<ShowPasswordButtonProps> = ({ passwordRef }) => {
  return (
    <StyledShowPasswordButton
      type="button"
      aria-label="Toggle password visibility"
      onClick={() => togglePasswordVisibility(passwordRef)}
    >
      <EyeIcon />
    </StyledShowPasswordButton>
  );
};

export default ShowPasswordButton;
