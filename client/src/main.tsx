import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import logoWithText from './assets/img/logo_with_text.svg';
import Providers from './context/Providers';
import { logger } from './helpers/logger';
import { installDevAnvilProvider } from './dev/anvilProvider';

// dev：VITE_DEV_ANVIL_RPC 配置时兜底注入 EIP-1193 代理（真钱包优先让位）。
installDevAnvilProvider();
import enMessages from './context/localization/locales/en.json';
import zhMessages from './context/localization/locales/zh.json';
import deMessages from './context/localization/locales/de.json';

const rootElement = document.getElementById('root');
const cookieBannerRoot = document.getElementById('cookie-banner');
const loadingScreen = document.getElementById('loading-screen');

if (
  import.meta.env.PROD &&
  import.meta.env.VITE_MAINTENANCE_MODE === 'true'
) {
  const lang = (typeof localStorage !== 'undefined' && localStorage.getItem('lang')) || 'en';
  const messages =
    lang === 'zh' ? zhMessages
    : lang === 'de' ? deMessages
    : enMessages;
  const maintenanceText = messages.maintenance_message || enMessages.maintenance_message;
  const brandAlt = messages['maintenance_brand-alt'] || enMessages['maintenance_brand-alt'];
  const template = `
    <div style="width: 100%; padding: 0 1.5rem; min-height: 100dvh; display: flex; flex-direction: column; justify-content: center; align-items: center; overflow: hidden; background-color: #ffffff;">
      <img style="width: 100%; max-width: 320px;" src=${logoWithText} alt="${brandAlt}">
      <p style="font-size: 1.5rem; font-family: 'Inter', sans-serif; color: #475569; text-align: center; margin-top: 3rem; padding: 1rem 2rem; background: rgba(241, 245, 249, 0.9); border: 1px solid rgba(226, 232, 240, 0.9); border-radius: 1rem;">${maintenanceText}</p>
    </div>
  `;
  if (loadingScreen) loadingScreen.style.display = 'none';
  if (rootElement) {
    rootElement.innerHTML = template;
    rootElement.style.display = 'block';
  }
} else {
  if (rootElement) {
    const root = createRoot(rootElement);
    root.render(
      <React.StrictMode>
        <Providers>
          <App />
        </Providers>
      </React.StrictMode>,
    );
  }

  // Hide loading screen and show app content when window has fully loaded
  window.onload = () => {
    setTimeout(() => {
      if (loadingScreen) loadingScreen.style.display = 'none';
      if (rootElement) rootElement.style.display = 'block';
      if (cookieBannerRoot) cookieBannerRoot.style.display = 'block';
    }, 1000);
  };
}