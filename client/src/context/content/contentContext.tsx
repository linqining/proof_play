import { createContext, useContext } from 'react';

export interface StaticPage {
  slug: string;
  title: string;
  content: string;
}

export interface ContentContextType {
  isLoading: boolean;
  staticPages: StaticPage[] | null;
  getLocalizedString: (key: string) => string;
}

const contentContext = createContext<ContentContextType | undefined>(undefined);

export const useContentContext = (): ContentContextType => {
  const context = useContext(contentContext);
  if (context === undefined) {
    throw new Error('useContentContext must be used within a ContentProvider');
  }
  return context;
};

export default contentContext;
