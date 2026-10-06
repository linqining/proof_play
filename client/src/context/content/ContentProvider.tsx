import React, { useState, useEffect } from 'react';
import ContentContext, { ContentContextType } from './contentContext';
import useContentful from '../../hooks/useContentful';
import { useLocaContext } from '../localization/locaContext';

import en from '../localization/locales/en.json';
import zh from '../localization/locales/zh.json';
import de from '../localization/locales/de.json';

// Locale JSON is a nested object tree (e.g. whitepaper.ch1.title). We keep the
// type permissive so a `getLocalizedString('a.b.c')` lookup walks the tree at
// runtime rather than collapsing it to flat keys at module load time.
const localTranslations: Record<string, unknown> = { en, zh, de };

interface ContentProviderProps {
  children: React.ReactNode;
}

const ContentProvider: React.FC<ContentProviderProps> = ({ children }) => {
  const { lang } = useLocaContext();
  const contentfulClient = useContentful();

  const [isLoading, setIsLoading] = useState(true);
  const [staticPages, setStaticPages] = useState<ContentContextType['staticPages']>(null);
  const [localizedStrings, setLocalizedStrings] = useState<Record<string, string> | null>(null);

  useEffect(() => {
    setIsLoading(true);

    fetchContent().finally(() => {
      setIsLoading(false);
    });
    // eslint-disable-next-line
  }, [lang]);

  const fetchContent = (): Promise<void> => {
    if (!contentfulClient) {
      return Promise.resolve();
    }

    return Promise.all([
      contentfulClient
        .getEntries({ content_type: 'key', locale: lang })
        .then((res) => {
          const localizedStrings: Record<string, string> = {};

          res.items.forEach(
            (item) =>
              (localizedStrings[(item.fields as { keyName: string }).keyName] =
                (item.fields as { value: { fields: { value: string } } }).value.fields.value),
          );

          setLocalizedStrings(localizedStrings);
        })
        .catch(() => {
          setLocalizedStrings({});
        }),
      contentfulClient
        .getEntries({ content_type: 'staticPage', locale: lang })
        .then((res) => {
          setStaticPages(
            res.items.map((item) => {
              const fields = item.fields as { slug: string; title: string; content: { fields: { value: string } } };
              return {
                slug: fields.slug,
                title: fields.title,
                content: fields.content.fields.value,
              };
            }),
          );
        }),
    ]).then(() => undefined);
  };

  /**
   * Resolve a translation key. Supports dot-notation (e.g. "whitepaper.ch1.title")
   * by walking into the nested JSON structure. Falls back to the literal key when
   * the translation is missing — so missing keys are obvious in QA without
   * breaking the page.
   */
  const getLocalizedString = (key: string): string => {
    if (localizedStrings && localizedStrings[key]) {
      return localizedStrings[key];
    }
    const localDict = localTranslations[lang] as unknown as Record<string, unknown> | undefined;
    if (localDict) {
      const parts = key.split('.');
      let cur: any = localDict;
      for (const p of parts) {
        if (cur && typeof cur === 'object' && p in cur) {
          cur = cur[p];
        } else {
          cur = undefined;
          break;
        }
      }
      if (typeof cur === 'string') {
        return cur;
      }
    }
    return key;
  };

  return (
    <ContentContext.Provider
      value={{ isLoading, staticPages, getLocalizedString }}
    >
      {children}
    </ContentContext.Provider>
  );
};

export default ContentProvider;
