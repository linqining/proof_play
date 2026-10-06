import { useEffect } from 'react';
import { useLocation, useNavigationType } from 'react-router-dom';
import config from '../../clientConfig';

const GoogleAnalytics: React.FC = () => {
  const location = useLocation();
  const navigationType = useNavigationType();

  useEffect(() => {
    const gtag = window.gtag;

    if (navigationType === 'PUSH' && gtag && typeof gtag === 'function') {
      gtag('config', config.googleAnalyticsTrackingId, {
        page_title: document.title,
        page_location: window.location.href,
        page_path: location.pathname,
      });
    }
  }, [location, navigationType]);

  return null;
};

export default GoogleAnalytics;
