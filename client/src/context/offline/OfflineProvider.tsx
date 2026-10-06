import React, { useCallback, useEffect, useRef } from 'react';
import OfflineContext from './offlineContext';
import useServiceWorker from '../../hooks/useServiceWorker';
import { useModalContext } from '../modal/modalContext';
import Text from '../../components/typography/Text';
import { useContentContext } from '../content/contentContext';

interface OfflineProviderProps {
  children: React.ReactNode;
}

const OfflineProvider: React.FC<OfflineProviderProps> = ({ children }) => {
  const { openModal } = useModalContext();
  const { getLocalizedString } = useContentContext();

  // Hold the latest `updateServiceWorker` in a ref so the callback below can be
  // defined (as a useCallback) before `useServiceWorker` is called, breaking
  // the previous use-before-define cycle.
  const updateServiceWorkerRef = useRef<(() => void) | null>(null);

  const onUpdateServiceWorker = useCallback(() => {
    openModal(
      () => (
        <Text>{getLocalizedString('service_worker-update_available')}</Text>
      ),
      getLocalizedString('service_worker-update_headline'),
      getLocalizedString('service_worker-update_confirm_btn_txt'),
      () => updateServiceWorkerRef.current?.(),
    );
  }, [openModal, getLocalizedString]);

  const [updateServiceWorker] = useServiceWorker(onUpdateServiceWorker);

  useEffect(() => {
    updateServiceWorkerRef.current = updateServiceWorker;
  }, [updateServiceWorker]);

  return <OfflineContext.Provider value={{}}>{children}</OfflineContext.Provider>;
};

export default OfflineProvider;
