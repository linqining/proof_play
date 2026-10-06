import React, { createContext } from 'react';

export type AuthMethod = 'wallet' | null;

export interface AuthContextType {
  isLoggedIn: boolean;
  logout: () => void;
  loadUser: (token: string) => Promise<void>;
  walletAddress: string | null;
  disconnectWallet: () => void;
  authMethod: AuthMethod;
  loginWithZChain: () => Promise<void>;
  loginWithMonad: () => Promise<void>;
}

const authContext = createContext<AuthContextType | undefined>(undefined);

export default authContext;