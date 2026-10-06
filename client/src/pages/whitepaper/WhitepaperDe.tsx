import React from 'react';
import WhitepaperBody from './WhitepaperBody';
import dict from '../../context/localization/locales/de.json';

/**
 * German edition of the whitepaper.
 *
 * Locale JSON is imported statically so the bundle is ready on first paint
 * — no async i18n loader, no fallback. The three language components are
 * selected at the route layer based on the current language.
 */
const t = (key: string): string => {
  const parts = key.split('.');
  let cur: any = dict;
  for (const p of parts) {
    if (cur && typeof cur === 'object' && p in cur) cur = cur[p];
    else return key;
  }
  return typeof cur === 'string' ? cur : key;
};

const WhitepaperDe: React.FC = () => <WhitepaperBody t={t} />;

export default WhitepaperDe;
