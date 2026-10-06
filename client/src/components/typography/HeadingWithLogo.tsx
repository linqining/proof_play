import React from 'react';
import Heading from './Heading';
import LogoIcon from '../logo/LogoIcon';
import styled from 'styled-components';
import Hider from '../layout/Hider';

const StyledHeadingWithLogo = styled.div`
  svg {
    margin-right: 0.5rem;
    width: ${({ theme }) => theme.fonts.fontSizeH3};
  }

  ${Heading} {
    display: flex;
    justify-content: center;
    align-items: center;
    margin-bottom: 2rem;
    color: ${({ theme }) => theme.colors.primaryCta};
  }
`;

interface HeadingWithLogoProps {
  children?: React.ReactNode;
  textCentered?: boolean;
  textCenteredOnMobile?: boolean;
  hideIconOnMobile?: boolean;
}

const HeadingWithLogo: React.FC<HeadingWithLogoProps> = ({
  children,
  textCentered = false,
  textCenteredOnMobile = false,
  hideIconOnMobile = true,
}) => {
  return (
    <StyledHeadingWithLogo>
      <Heading
        as="h2"
        headingClass="h4"
        textCentered={textCentered}
        textCenteredOnMobile={textCenteredOnMobile}
      >
        {hideIconOnMobile ? (
          <Hider hideOnMobile>
            <LogoIcon />
          </Hider>
        ) : (
          <LogoIcon />
        )}{' '}
        {children}
      </Heading>
    </StyledHeadingWithLogo>
  );
};

export default HeadingWithLogo;
