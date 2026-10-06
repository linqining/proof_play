import React, { useContext, useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Navbar from '../components/navigation/Navbar';
import Footer from '../components/navigation/Footer';
import NavMenu from '../components/navigation/NavMenu';
import CookieBanner from '../components/cookies/CookieBanner';
import LoginModal from '../components/auth/LoginModal';
import useNavMenu from '../hooks/useNavMenu';
import useCookie from '../hooks/useCookie';
import { useGlobalContext } from '../context/global/globalContext';
import authContext from '../context/auth/authContext';
import socketContext from '../context/websocket/socketContext';
import { useLocaContext } from '../context/localization/locaContext';
import { useContentContext } from '../context/content/contentContext';
import { useModalContext } from '../context/modal/modalContext';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const { chipsAmount, userName } = useGlobalContext();
  const { isLoggedIn, disconnectWallet } = useContext(authContext)!;
  const { cleanUp } = useContext(socketContext)!;
  const { lang, setLang } = useLocaContext();
  const { staticPages } = useContentContext();
  const { openModal } = useModalContext();

  const [showNavMenu, openNavMenu, closeNavMenu] = useNavMenu();
  const [isCookieSet, setCookie] = useCookie('cookies-accepted', true);

  const location = useLocation();
  const navigate = useNavigate();
  const [showLoginModal, setShowLoginModal] = useState(false);

  // ProtectedRoute 重定向时会通过 location.state 传递 showLogin 标志
  useEffect(() => {
    const state = location.state as { showLogin?: boolean } | null;
    if (state?.showLogin) {
      setShowLoginModal(true);
      // 清除 location.state，避免刷新或前进/后退时重复触发
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location, navigate]);

  const openSignIn = () => setShowLoginModal(true);
  const closeSignIn = () => setShowLoginModal(false);

  // 统一的登出处理：清理 socket + 断开钱包 + 清除应用状态
  const handleLogout = () => {
    cleanUp();
    disconnectWallet();
  };

  // 根据路由判断是否隐藏布局
  const hideLayout = location.pathname.includes('/play');

  // 整体已改为亮色主题，固定使用 light variant
  const themeVariant = 'light';

  return (
    <div id="layout-wrapper">
      {!hideLayout && (
        <Navbar
          chipsAmount={chipsAmount}
          loggedIn={isLoggedIn}
          openNavMenu={openNavMenu}
          onSignIn={openSignIn}
          onLogout={handleLogout}
          className="blur-target"
          variant={themeVariant}
        />
      )}
      {showNavMenu && (
        <NavMenu
          onClose={closeNavMenu}
          userName={userName}
          chipsAmount={chipsAmount}
          lang={lang}
          setLang={setLang}
          openModal={openModal}
          loggedIn={isLoggedIn}
          onLogout={handleLogout}
        />
      )}
      <main className="blur-target">{children}</main>
      {/* {!hideLayout && (
        <Footer
          className="blur-target"
          setLang={setLang}
          staticPages={staticPages}
          variant={themeVariant}
        />
      )} */}
      {!isCookieSet && (
        <CookieBanner clickHandler={() => setCookie('1', 365)} />
      )}
      <LoginModal isOpen={showLoginModal} onClose={closeSignIn} />
    </div>
  );
};

export default MainLayout;
