import React, { useContext } from 'react';
import logoSvg from '../../assets/img/logo-icon-transparent.svg';
import contentContext from '../../context/content/contentContext';

interface LogoIconProps {
  color?: string;
  size?: number;
}

const LogoIcon: React.FC<LogoIconProps> = ({ size = 40 }) => {
  const { getLocalizedString: t } = useContext(contentContext)!;
  return (
    <img
      src={logoSvg}
      alt={t('common_logo-alt')}
      width={size}
      height={size}
      style={{ display: 'block' }}
    />
  );
};

export default LogoIcon;
