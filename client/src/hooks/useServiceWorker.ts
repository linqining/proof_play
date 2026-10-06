import { useState, useEffect } from 'react';
import * as serviceWorker from '../serviceWorker';

interface ServiceWorkerData {
  waitingWorker?: ServiceWorker | null;
  newVersionAvailable: boolean;
}

type UseServiceWorkerReturn = [() => void];

const useServiceWorker = (callback: () => void): UseServiceWorkerReturn => {
  const [serviceWorkerData, setServiceWorkerData] = useState<ServiceWorkerData | null>(null);

  useEffect(() => {
    serviceWorker.register({ onUpdate: onServiceWorkerUpdate });

    // eslint-disable-next-line
  }, []);

  useEffect(() => {
    serviceWorkerData && serviceWorkerData.newVersionAvailable && callback();
    // eslint-disable-next-line
  }, [serviceWorkerData]);

  const onServiceWorkerUpdate = (registration: ServiceWorkerRegistration | undefined): void =>
    setServiceWorkerData({
      waitingWorker: registration && registration.waiting,
      newVersionAvailable: true,
    });

  const updateServiceWorker = (): void => {
    const { waitingWorker } = serviceWorkerData!;
    waitingWorker && waitingWorker.postMessage({ type: 'SKIP_WAITING' });
    setServiceWorkerData({ newVersionAvailable: false });
    window.location.reload();
  };

  return [updateServiceWorker];
};

export default useServiceWorker;
