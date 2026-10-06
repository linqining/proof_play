import React, { useContext } from 'react';
import { Link } from 'react-router-dom';
import styled from 'styled-components';
import Text from '../typography/Text';
import ColoredText from '../typography/ColoredText';
import contentContext, { StaticPage } from '../../context/content/contentContext';

interface FooterProps {
  className?: string;
  setLang: (lang: string) => void;
  staticPages: StaticPage[] | null;
  variant?: 'light' | 'dark';
}

const StyledFooter = styled.footer`
  text-align: center;
  padding: 2rem 0;
  font-size: 1rem;
  background-color: ${(props: any) => props.theme.colors.lightestBg};
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
`;

/* FooterText / StaticPageLink use theme colors instead of inline `style`
   attributes so consumers can theme the footer without prop-drilling
   values. */
const FooterText = styled(Text)`
  a {
    color: ${({ theme }) => theme.colors.mutedText};
    transition: color 0.2s ease;
    &:hover {
      color: ${({ theme }) => theme.colors.secondaryCta};
    }
  }
`;

const StaticPageLink = styled(Link)`
  color: ${({ theme }) => theme.colors.mutedText};
  transition: color 0.2s ease;

  &:hover {
    color: ${({ theme }) => theme.colors.secondaryCta};
  }
`;

/* LangLink: an in-page anchor that swaps the language. Uses href="#"
   (a real in-document target) plus preventDefault; never the bogus
   "!" href. */
const LangLink = styled.a`
  color: ${({ theme }) => theme.colors.mutedText};
  transition: color 0.2s ease;
  cursor: pointer;
  text-decoration: none;

  &:hover {
    color: ${({ theme }) => theme.colors.secondaryCta};
    text-decoration: underline;
  }
`;

const Footer: React.FC<FooterProps> = ({ className, setLang, staticPages }) => {
  const { getLocalizedString } = useContext(contentContext)!;

  const handleLangClick = (e: React.MouseEvent, lang: string) => {
    e.preventDefault();
    setLang(lang);
  };

  return (
    <StyledFooter className={className}>
      <FooterText textAlign="center" fontSize="0.9rem">
        {getLocalizedString('footer-lang_selection_txt')}:{'  '}
        <LangLink href="#lang-en" onClick={(e) => handleLangClick(e, 'en')}>
          EN
        </LangLink>{' '}
        |{' '}
        <LangLink href="#lang-zh" onClick={(e) => handleLangClick(e, 'zh')}>
          中文
        </LangLink>{' '}
        |{' '}
        <LangLink href="#lang-de" onClick={(e) => handleLangClick(e, 'de')}>
          DE
        </LangLink>
      </FooterText>
      <Text textAlign="center" fontSize="0.9rem">
        {staticPages &&
          staticPages.map((page, index, array) => {
            const component = (
              <StaticPageLink key={page.slug} to={`/${page.slug}`}>
                {page.title}
              </StaticPageLink>
            );
            if (index < array.length - 1)
              return (
                <span key={page.slug}>
                  {component}
                  {' | '}
                </span>
              );
            else return component;
          })}
      </Text>
      <Text textAlign="center" fontSize="0.9rem">
        <ColoredText>{getLocalizedString('footer-copyright_txt')}</ColoredText>
      </Text>
    </StyledFooter>
  );
};

export default Footer;
