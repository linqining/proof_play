import { createContext, useContext } from 'react';

export interface OfflineContextType {
  // Currently no values exposed; provider wraps children for service worker logic
}

const offlineContext = createContext<OfflineContextType | undefined>(undefined);

export const useOfflineContext = (): OfflineContextType => {
  const context = useContext(offlineContext);
  if (context === undefined) {
    throw new Error('useOfflineContext must be used within an OfflineProvider');
  }
  return context;
};

export default offlineContext;
