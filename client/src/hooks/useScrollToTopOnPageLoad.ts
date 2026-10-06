import { useEffect } from 'react';

const useScrollToTopOnPageLoad = (): void => {
  useEffect(() => {
    window.scrollTo(0, 0);
  }, []);
};

export default useScrollToTopOnPageLoad;
