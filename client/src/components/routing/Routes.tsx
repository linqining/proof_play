import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Dashboard from '../../pages/Dashboard';
import SecretPokerHomePage from '../../pages/SecretPokerHomePage';
import Play from '../../pages/Play';
import ProtectedRoute from './ProtectedRoute';
import StaticPage from '../../pages/StaticPage';
import NotFoundPage from '../../pages/NotFoundPage';
import Whitepaper from '../../pages/Whitepaper';
import contentContext from '../../context/content/contentContext';
import SecretPokerLobby from '../../pages/SecretPokerLobby';
import SecretPokerGameTable from '../../pages/SecretPokerGameTable';

const RoutesComponent: React.FC = () => {
  const { staticPages } = useContext(contentContext)!;

  return (
    <Routes>
      <Route path="/" element={<SecretPokerHomePage />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />
      {staticPages &&
        staticPages.map((page) => (
          <Route
            key={page.slug}
            path={`/${page.slug}`}
            element={<StaticPage title={page.title} content={page.content} />}
          />
        ))}
      <Route
        path="/play"
        element={
          <ProtectedRoute>
            <Play />
          </ProtectedRoute>
        }
      />
      <Route path="/lobby" element={<SecretPokerLobby />} />
      <Route path="/game/:gameId" element={<SecretPokerGameTable />} />
      {/* AUTH-FREE: /whitepaper is intentionally a public route — anonymous
          visitors must be able to read the whitepaper without being
          redirected to the home page with `state.showLogin: true`.
          Do NOT wrap this route in <ProtectedRoute />. The whitepaper
          component itself does not import `authContext`, so clicking
          any link inside it cannot trigger the login modal. */}
      <Route path="/whitepaper" element={<Whitepaper />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
};

import { useContext } from 'react';

export default RoutesComponent;