import { createContext, useContext } from 'react';

export interface LocaContextType {
  lang: string;
  setLang: React.Dispatch<React.SetStateAction<string>>;
}

const locaContext = createContext<LocaContextType | undefined>(undefined);

export const useLocaContext = (): LocaContextType => {
  const context = useContext(locaContext);
  if (context === undefined) {
    throw new Error('useLocaContext must be used within a LocaProvider');
  }
  return context;
};

export default locaContext;
