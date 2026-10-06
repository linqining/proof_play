import React from 'react';
import { Link } from 'react-router-dom';
import styled from 'styled-components';
import useScrollToTopOnPageLoad from '../hooks/useScrollToTopOnPageLoad';
import { useContentContext } from '../context/content/contentContext';

/**
 * 404（design/client C5）：巨型灰数字 + 标题 + 五条快捷出口，
 * 纸白底方角细线卡，无任何异品牌水印装饰。
 */

const Wrap = styled.main`
  min-height: 100dvh;
  background: ${({ theme }) => theme.colors.lightBg};
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 4rem 2rem;
  text-align: center;
`;

const Block = styled.div`
  max-width: 560px;
  width: 100%;
`;

const Big404 = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: clamp(96px, 20vw, 200px);
  font-weight: 800;
  line-height: 1;
  letter-spacing: -0.04em;
  color: ${({ theme }) => theme.colors.borderSubtle};
`;

const Title = styled.h2`
  font-size: 1.4rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  margin: 0.75rem 0 0.35rem;
`;

const Desc = styled.p`
  font-size: 0.9rem;
  color: ${({ theme }) => theme.colors.mutedText};
  margin: 0 0 1.75rem;
`;

const Exits = styled.div`
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 0.5rem;
`;

const Exit = styled(Link)`
  padding: 0.45rem 0.9rem;
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: ${({ theme }) => theme.radius.sm};
  background: ${({ theme }) => theme.colors.lightestBg};
  color: ${({ theme }) => theme.colors.fontColorDark};
  font-size: 0.85rem;
  text-decoration: none;

  &:hover {
    border-color: ${({ theme }) => theme.colors.success};
    color: ${({ theme }) => theme.colors.success};
  }
`;

const ExitPrimary = styled(Exit)`
  border-color: ${({ theme }) => theme.colors.success};
  background: ${({ theme }) => theme.colors.success};
  color: #fffdf7;

  &:hover {
    color: #fffdf7;
    background: ${({ theme }) => theme.colors.successStrong};
  }
`;

const NotFoundPage: React.FC = () => {
  const { getLocalizedString } = useContentContext();
  useScrollToTopOnPageLoad();

  return (
    <Wrap>
      <Block>
        <Big404>404</Big404>
        <Title>{getLocalizedString('notfound-heading_txt')}</Title>
        <Desc>{getLocalizedString('notfound-content_txt')}</Desc>
        <Exits>
          <ExitPrimary as={Link} to="/">
            {getLocalizedString('homepage_nav-home')}
          </ExitPrimary>
          <Exit as={Link} to="/lobby">
            {getLocalizedString('navbar_lobby_btn')}
          </Exit>
          <Exit as={Link} to="/dashboard">
            {getLocalizedString('navbar-dashboard_btn')}
          </Exit>
          <Exit as={Link} to="/whitepaper">
            {getLocalizedString('navbar-whitepaper_btn')}
          </Exit>
          <Exit as={Link} to="/game-rules">
            {getLocalizedString('main_page-open_rules')}
          </Exit>
        </Exits>
      </Block>
    </Wrap>
  );
};

export default NotFoundPage;
