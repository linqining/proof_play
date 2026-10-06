import React from 'react';
import theme from '../../styles/theme';

const HamburgerIcon: React.FC = () => (
  <svg
    width="40"
    height="40"
    viewBox="0 0 40 40"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <rect x="1" y="1" width="38" height="38" rx="3" fill="none" stroke={theme.colors.fontColorDark} strokeWidth="2" />
    <line
      x1="8"
      y1="17.3334"
      x2="32"
      y2="17.3334"
      stroke={theme.colors.fontColorDark}
      strokeWidth="2"
    />
    <line
      x1="8"
      y1="12"
      x2="32"
      y2="12"
      stroke={theme.colors.fontColorDark}
      strokeWidth="2"
    />
    <line
      x1="8"
      y1="22.6666"
      x2="30"
      y2="22.6666"
      stroke={theme.colors.fontColorDark}
      strokeWidth="2"
    />
    <line
      x1="8"
      y1="28"
      x2="28"
      y2="28"
      stroke={theme.colors.fontColorDark}
      strokeWidth="2"
    />
  </svg>
);

export default HamburgerIcon;
