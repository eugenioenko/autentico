import React, { useEffect, Suspense } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import { useAuth } from 'oidc-js-react';
import { IconMenu2 } from '@tabler/icons-react';
import Sidebar from './Sidebar';
import AppHeader from './AppHeader';
import Spinner from './Spinner';

const Dashboard = React.lazy(() => import('../pages/Dashboard'));
const ProfilePage = React.lazy(() => import('../pages/Profile'));
const SecurityPage = React.lazy(() => import('../pages/Security'));
const SessionsPage = React.lazy(() => import('../pages/Sessions'));
const TrustedDevicesPage = React.lazy(() => import('../pages/TrustedDevices'));
const ConnectedProvidersPage = React.lazy(() => import('../pages/ConnectedProviders'));

const pageTitles: Record<string, string> = {
  '/': 'Overview',
  '/profile': 'Profile',
  '/security': 'Security',
  '/sessions': 'Sessions',
  '/trusted-devices': 'Trusted Devices',
  '/connected-providers': 'Connected Providers',
};

const Layout: React.FC = () => {
  const { user, isLoading, isAuthenticated, actions } = useAuth();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  useEffect(() => {
    if (!isLoading && !isAuthenticated) actions.login();
  }, [isLoading, isAuthenticated, actions]);

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-dvh flex items-center justify-center bg-theme-bg">
        <Spinner />
      </div>
    );
  }

  const initials = (user?.claims?.preferred_username as string)?.[0]?.toUpperCase() || 'U';
  const pageTitle = pageTitles[location.pathname] ?? 'Account';

  return (
    <div className="min-h-dvh flex flex-col md:flex-row">
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <Sidebar
        open={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
        username={(user?.claims?.preferred_username as string) ?? ''}
        initials={initials}
        onLogout={actions.logout}
      />

      <main className="flex-1 flex flex-col min-w-0">
        <AppHeader
          title={pageTitle}
          onMenuOpen={() => setMobileMenuOpen(true)}
        />

        <div className="p-5 md:p-8 max-w-3xl">
          <Suspense
            fallback={
              <div className="flex justify-center pt-16">
                <div className="w-6 h-6 border-2 border-theme-fg/20 border-t-theme-fg rounded-full animate-spin" />
              </div>
            }
          >
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/profile" element={<ProfilePage />} />
              <Route path="/security" element={<SecurityPage />} />
              <Route path="/sessions" element={<SessionsPage />} />
              <Route path="/trusted-devices" element={<TrustedDevicesPage />} />
              <Route path="/connected-providers" element={<ConnectedProvidersPage />} />
            </Routes>
          </Suspense>
        </div>
      </main>

      <div className="fixed bottom-4 right-4 md:hidden">
        <button
          onClick={() => setMobileMenuOpen(true)}
          className="w-12 h-12 bg-theme-accent-bg text-theme-accent-fg rounded-full shadow-lg flex items-center justify-center"
        >
          <IconMenu2 size={20} />
        </button>
      </div>
    </div>
  );
};

export default Layout;
