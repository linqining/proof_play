import React from 'react';
import { useLocation } from 'react-router-dom';
import MainLayout from './layouts/_MainLayout';
import LoadingScreen from './components/loading/LoadingScreen';
import { useGlobalContext } from './context/global/globalContext';
import Routes from './components/routing/Routes';
import { useContentContext } from './context/content/contentContext';
import config from './clientConfig';
import GoogleAnalytics from './components/analytics/GoogleAnalytics';
import { logger } from './helpers/logger';

const AppInner: React.FC = () => {
  const { isLoading } = useGlobalContext();
  const { isLoading: contentIsLoading } = useContentContext();

  const location = useLocation();
  const showLoading = (isLoading || contentIsLoading);

  logger.log('[App] render:', { isLoading, contentIsLoading, showLoading, pathname: location.pathname });

  return (
    <>
      {showLoading ? (
        <LoadingScreen />
      ) : (
        <MainLayout>
          <Routes />
        </MainLayout>
      )}
      {config.isProduction && <GoogleAnalytics />}
    </>
  );
};

const App: React.FC = () => {
  return (
    <AppInner />
  );
};

export default App;