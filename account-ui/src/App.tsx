import { useMemo } from 'react';
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from 'oidc-js-react';
import type { OidcConfig } from 'oidc-js-react';
import { SettingsProvider, useSettings } from './context/SettingsContext';
import AuthBridge from './components/AuthBridge';
import Layout from './components/Layout';
import Callback from './pages/Callback';

const queryClient = new QueryClient();

const BASENAME = '/account';
const CLIENT_ID = 'autentico-account';
const REDIRECT_URI = window.location.origin + BASENAME + '/callback';

function AuthWrapper({ children }: { children: React.ReactNode }) {
  const { oauth_path } = useSettings();
  const navigate = useNavigate();

  const config: OidcConfig = useMemo(() => ({
    issuer: window.location.origin + oauth_path,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scopes: ['openid', 'profile', 'email', 'offline_access'],
  }), [oauth_path]);

  const onLogin = useMemo(() => (returnTo: string) => {
    const path = returnTo.startsWith(BASENAME)
      ? returnTo.slice(BASENAME.length) || '/'
      : returnTo;
    navigate(path, { replace: true });
  }, [navigate]);

  return (
    <AuthProvider config={config} fetchProfile={false} onLogin={onLogin}>
      <AuthBridge />
      {children}
    </AuthProvider>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SettingsProvider>
        <BrowserRouter basename={BASENAME}>
          <AuthWrapper>
            <Routes>
              <Route path="/callback" element={<Callback />} />
              <Route path="/*" element={<Layout />} />
            </Routes>
          </AuthWrapper>
        </BrowserRouter>
      </SettingsProvider>
    </QueryClientProvider>
  );
}

export default App;
