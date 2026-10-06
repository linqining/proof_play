import React from 'react';
import ReactDOM from 'react-dom';
import styled from 'styled-components';
import Button from '../buttons/Button';
import { Link } from 'react-router-dom';
import { useContentContext } from '../../context/content/contentContext';

const Wrapper = styled.div`
  position: fixed;
  padding: 0 1.5rem;
  bottom: 0;
  left: 0;
  width: 100%;
  z-index: 50;
  text-align: center;
  pointer-events: none;
`;

const StyledCookieBanner = styled.div`
  background-color: ${({ theme }) => theme.colors.playingCardBg};
  color: ${({ theme }) => theme.colors.fontColorDark};
  padding: 0.5rem;
  font-size: 1rem;
  text-align: center;
  width: 100%;
  max-width: 760px;
  margin: 1rem auto 1.5rem auto;
  display: flex;
  border-radius: calc(${({ theme }) => theme.other.stdBorderRadius} - 1rem);
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  pointer-events: all;
`;

const ContentWrapper = styled.div`
  display: flex;
  align-items: center;
  margin: 0 auto;

  @media screen and (max-width: 468px) {
    flex-direction: column;
  }
`;

const Content = styled.div`
  padding: 1em;
  color: ${({ theme }) => theme.colors.fontColorDark};
  font-size: 0.85rem;
  text-align: left;
  width: 70%;

  @media screen and (max-width: 468px) {
    width: 100%;
    padding: 0.5em;
  }
`;

const ButtonWrapper = styled.div`
  display: flex;
  flex-wrap: wrap;
  justify-content: space-around;
  width: 30%;

  & > ${Button} {
    margin: 0.5em;
    min-width: 6rem;
    font-size: 0.85rem;
  }

  @media screen and (max-width: 468px) {
    width: 100%;
    justify-content: center;
  }
`;

interface CookieBannerProps {
  clickHandler: () => void;
  className?: string;
}

const CookieBanner: React.FC<CookieBannerProps> = ({ clickHandler, className }) => {
  const { getLocalizedString } = useContentContext();

  return ReactDOM.createPortal(
    <Wrapper className={className}>
      <StyledCookieBanner>
        <ContentWrapper>
          <Content>{getLocalizedString('cookiebanner-text')}</Content>
          <ButtonWrapper>
            <Button small primary onClick={clickHandler}>
              {getLocalizedString('cookiebanner-confirm_btn_txt')}
            </Button>
            <Button
              as={Link}
              to="/privacy"
              secondary
              small
              aria-label={getLocalizedString('cookiebanner-info_aria')}
            >
              {getLocalizedString('cookiebanner-info_btn_txt')}
            </Button>
          </ButtonWrapper>
        </ContentWrapper>
      </StyledCookieBanner>
    </Wrapper>,
    document.getElementById('cookie-banner') as HTMLElement,
  );
};

export default CookieBanner;
