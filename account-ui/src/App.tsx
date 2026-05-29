import { useMemo } from 'react';
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from 'oidc-js-react';
import type { OidcConfig } from 'oidc-js-react';
import { SettingsProvider, useSettings } from './context/SettingsContext';
import AuthBridge from './components/AuthBridge';
import Layout from './components/Layout';
import Callback from './pages/Callback';
import Device from './pages/Device';
import { RequireAuth } from 'oidc-js-react';
import Spinner from './components/Spinner';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1 } },
});

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
    expiryBuffer: 0,
  }), [oauth_path]);

  const onLogin = useMemo(() => (returnTo: string) => {
    sessionStorage.removeItem('oidc_retry');
    const path = returnTo.startsWith(BASENAME)
      ? returnTo.slice(BASENAME.length) || '/'
      : returnTo;
    navigate(path, { replace: true });
  }, [navigate]);

  const onError = useMemo(() => (err: Error) => {
    // Auth state errors (missing or mismatched) mean the callback opened in a
    // different context (e.g. magic link from email). Restart the login flow
    // once — the IdP session will auto-login.
    const isStateError = err.message?.includes('Missing auth state') || err.message?.includes('State parameter');
    if (isStateError && !sessionStorage.getItem('oidc_retry')) {
      sessionStorage.setItem('oidc_retry', '1');
      window.location.href = BASENAME;
      return;
    }
    sessionStorage.removeItem('oidc_retry');
  }, []);

  return (
    <AuthProvider config={config} fetchProfile={false} onLogin={onLogin} onError={onError}>
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
              <Route path="/device/:code" element={
                <RequireAuth fallback={<div className="min-h-dvh flex items-center justify-center bg-theme-bg"><Spinner /></div>}>
                  <Device />
                </RequireAuth>
              } />
              <Route path="/device" element={
                <RequireAuth fallback={<div className="min-h-dvh flex items-center justify-center bg-theme-bg"><Spinner /></div>}>
                  <Device />
                </RequireAuth>
              } />
              <Route path="/*" element={<Layout />} />
            </Routes>
          </AuthWrapper>
        </BrowserRouter>
      </SettingsProvider>
    </QueryClientProvider>
  );
}

export default App;
