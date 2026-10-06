import React, { useContext } from 'react';
import { Navigate } from 'react-router-dom';
import authContext from '../../context/auth/authContext';
import { useGlobalContext } from '../../context/global/globalContext';
import Container from '../layout/Container';
import Loader from '../loading/Loader';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const auth = useContext(authContext);
  const { isLoading } = useGlobalContext();

  // 等待 auth 初始化完成再决定是否重定向。
  // 否则用户刷新 /play 时，isLoggedIn 尚未从 loadUser 恢复为 true，
  // 会被错误地重定向到首页。
  if (isLoading) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
      </Container>
    );
  }

  const isLoggedIn = !!auth?.isLoggedIn;

  if (!isLoggedIn) {
    return <Navigate to="/" state={{ showLogin: true }} replace />;
  }

  return <>{children}</>;
};

export default ProtectedRoute;
