import React, { useState } from 'react';
import GlobalContext from './globalContext';
import { GlobalContextType } from './globalContext';

interface GlobalStateProps {
  children: React.ReactNode;
}

const GlobalState: React.FC<GlobalStateProps> = ({ children }) => {
  const [isLoading, setIsLoading] = useState<GlobalContextType['isLoading']>(true);
  const [id, setId] = useState<GlobalContextType['id']>(null);
  const [userName, setUserName] = useState<GlobalContextType['userName']>(null);
  const [email, setEmail] = useState<GlobalContextType['email']>(null);
  const [chipsAmount, setChipsAmount] = useState<GlobalContextType['chipsAmount']>(null);
  const [strkBalance, setStrkBalance] = useState<GlobalContextType['strkBalance']>(null);
  const [tables, setTables] = useState<GlobalContextType['tables']>(null);
  const [players, setPlayers] = useState<GlobalContextType['players']>(null);

  return (
    <GlobalContext.Provider
      value={{
        isLoading,
        setIsLoading,
        userName,
        setUserName,
        email,
        setEmail,
        chipsAmount,
        setChipsAmount,
        strkBalance,
        setStrkBalance,
        id,
        setId,
        tables,
        setTables,
        players,
        setPlayers,
      }}
    >
      {children}
    </GlobalContext.Provider>
  );
};

export default GlobalState;
