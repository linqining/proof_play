import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import LocaContext from './locaContext';
import { LocaContextType } from './locaContext';

interface LocaProviderProps {
  children: React.ReactNode;
}

const initialState = localStorage.getItem('lang') || 'en';

const LocaProvider: React.FC<LocaProviderProps> = ({ children }) => {
  const location = useLocation();
  const [lang, setLang] = useState<LocaContextType['lang']>(initialState);

  useEffect(() => {
    const langParam = new URLSearchParams(location.search).get('lang');
    langParam && setLang(langParam);
    // eslint-disable-next-line
  }, []);

  useEffect(() => {
    localStorage.setItem('lang', lang);
    document.documentElement.setAttribute('lang', lang);
    // eslint-disable-next-line
  }, [lang]);

  return (
    <LocaContext.Provider value={{ lang, setLang }}>
      {children}
    </LocaContext.Provider>
  );
};

export default LocaProvider;
