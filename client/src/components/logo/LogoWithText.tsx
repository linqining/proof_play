import React, { useContext } from 'react';
import logoWithTextSvg from '../../assets/img/logo_with_text.svg';
import styled from 'styled-components';
import contentContext from '../../context/content/contentContext';

const LogoImage = styled.img`
  display: block;
  height: 50px;
  width: auto;
`;

const LogoWithText: React.FC = () => {
  const { getLocalizedString: t } = useContext(contentContext)!;
  return (
    <LogoImage
      src={logoWithTextSvg}
      alt={t('common_logo-alt')}
    />
  );
};

export default LogoWithText;
