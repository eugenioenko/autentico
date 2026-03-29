import React, { useEffect, Suspense } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { IconMenu2 } from '@tabler/icons-react';
import Sidebar from './Sidebar';
import AppHeader from './AppHeader';
import Spinner from './Spinner';
import { useSettings } from '../context/SettingsContext';

const Dashboard = React.lazy(() => import('../pages/Dashboard'));
const ProfilePage = React.lazy(() => import('../pages/ProfilePage'));
const SecurityPage = React.lazy(() => import('../pages/SecurityPage'));
const SessionsPage = React.lazy(() => import('../pages/SessionsPage'));
const TrustedDevicesPage = React.lazy(() => import('../pages/TrustedDevicesPage'));
const ConnectedProvidersPage = React.lazy(() => import('../pages/ConnectedProvidersPage'));

const pageTitles: Record<string, string> = {
  '/': 'Overview',
  '/profile': 'Profile',
  '/security': 'Security',
  '/sessions': 'Sessions',
  '/trusted-devices': 'Trusted Devices',
  '/connected-providers': 'Connected Providers',
};

const Layout: React.FC = () => {
  const { user, logout, isLoading, signinRedirect } = useAuth();
  const location = useLocation();
  const settings = useSettings();
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  useEffect(() => {
    if (!isLoading && !user) signinRedirect();
  }, [user, isLoading, signinRedirect]);

  if (isLoading || !user) {
    return (
      <div className="min-h-dvh flex items-center justify-center bg-theme-bg">
        <Spinner />
      </div>
    );
  }

  const initials = user.profile.preferred_username?.[0]?.toUpperCase() || 'U';
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
        username={user.profile.preferred_username ?? ''}
        initials={initials}
        appName={settings.theme_title}
        onLogout={logout}
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
