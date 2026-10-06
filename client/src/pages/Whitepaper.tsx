import React from 'react';
import { useLocaContext } from '../context/localization/locaContext';
import useScrollToTopOnPageLoad from '../hooks/useScrollToTopOnPageLoad';
import WhitepaperEn from './whitepaper/WhitepaperEn';
import WhitepaperZh from './whitepaper/WhitepaperZh';
import WhitepaperDe from './whitepaper/WhitepaperDe';

/**
 * Whitepaper route entry.
 *
 * Three language components live in `./whitepaper/`:
 *   - WhitepaperEn.tsx  (English, imports en.json)
 *   - WhitepaperZh.tsx  (Chinese, imports zh.json)
 *   - WhitepaperDe.tsx  (German,  imports de.json)
 *
 * All three reuse the same presentational tree in `./whitepaper/WhitepaperBody.tsx`,
 * so language switching only swaps the data, not the markup.
 *
 * Why three files instead of one with dot-notation i18n?
 *   1. The whitepaper is a long, mostly-static document — splitting it
 *      by language keeps each variant self-contained and reviewable.
 *   2. Locale JSON is statically imported, so the first paint is always
 *      in the user's selected language with no async loader.
 *   3. Other long-form content in this app (notices, marketing copy) is
 *      handled in the ContentProvider; the whitepaper is large enough
 *      to warrant its own per-language entry point.
 *
 * AUTH-FREE: this route is intentionally NOT wrapped in <ProtectedRoute />.
 * Anonymous visitors can read the whitepaper without being bounced to the
 * home page login modal. The whitepaper body also embeds its own
 * LanguageSwitcher, so the page is fully self-sufficient for anonymous
 * readers — it doesn't depend on the global Navbar's language UI.
 */
const Whitepaper: React.FC = () => {
  useScrollToTopOnPageLoad();
  const { lang } = useLocaContext();

  switch (lang) {
    case 'zh':
      return <WhitepaperZh />;
    case 'de':
      return <WhitepaperDe />;
    case 'en':
    default:
      return <WhitepaperEn />;
  }
};

export default Whitepaper;
