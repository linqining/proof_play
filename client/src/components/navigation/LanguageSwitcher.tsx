import React, { useContext } from 'react';
import styled from 'styled-components';
import { useLocaContext } from '../../context/localization/locaContext';
import contentContext from '../../context/content/contentContext';

const languages = [
  { code: 'en', label: 'EN' },
  { code: 'zh', label: 'ZH' },
  { code: 'de', label: 'DE' },
];

const LangSwitcherWrap = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.15rem;
  padding: 0.2rem;
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
`;

const LangOption = styled.button<{ $active: boolean }>`
  border: none;
  background: ${({ $active, theme }) =>
    $active ? theme.colors.brandGradient : 'transparent'};
  color: ${({ $active, theme }) =>
    $active ? theme.colors.lightestBg : theme.colors.mutedText};
  cursor: pointer;
  /* Apple HIG: 44x44 touch target */
  min-width: 44px;
  min-height: 44px;
  padding: 0 0.75rem;
  border-radius: ${({ theme }) => theme.radius.xs};
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1;
  transition: color 0.2s ease;

  &:hover:not([aria-pressed='true']) {
    color: ${({ theme }) => theme.colors.secondaryCta};
  }

  &:focus-visible {
    outline: 2px solid ${({ theme }) => theme.colors.brandPurple};
    outline-offset: 2px;
  }
`;

const LanguageSwitcher: React.FC = () => {
  const { lang, setLang } = useLocaContext();
  const { getLocalizedString } = useContext(contentContext)!;
  return (
    <LangSwitcherWrap role="group" aria-label={getLocalizedString('language-switcher_aria')}>
      {languages.map((l) => (
        <LangOption
          key={l.code}
          $active={lang === l.code}
          onClick={() => setLang(l.code)}
          aria-pressed={lang === l.code}
        >
          {l.label}
        </LangOption>
      ))}
    </LangSwitcherWrap>
  );
};

export default LanguageSwitcher;
