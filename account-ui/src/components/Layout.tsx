import React, { useEffect, Suspense } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import {
  IconUser, IconShield, IconKey, IconHistory, IconLogout,
  IconMenu2, IconX, IconDevices, IconLink,
} from '@tabler/icons-react';
import SidebarItem from './SidebarItem';
import Spinner from './Spinner';
import { cn } from '../lib/utils';

const Dashboard = React.lazy(() => import('../pages/Dashboard'));
const ProfilePage = React.lazy(() => import('../pages/ProfilePage'));
const SecurityPage = React.lazy(() => import('../pages/SecurityPage'));
const SessionsPage = React.lazy(() => import('../pages/SessionsPage'));
const TrustedDevicesPage = React.lazy(() => import('../pages/TrustedDevicesPage'));
const ConnectedProvidersPage = React.lazy(() => import('../pages/ConnectedProvidersPage'));

const navItems = [
  { to: '/', icon: IconShield, label: 'Overview' },
  { to: '/profile', icon: IconUser, label: 'Profile' },
  { to: '/security', icon: IconKey, label: 'Security' },
  { to: '/sessions', icon: IconHistory, label: 'Sessions' },
  { to: '/trusted-devices', icon: IconDevices, label: 'Trusted Devices' },
  { to: '/connected-providers', icon: IconLink, label: 'Connected Providers' },
];

const Layout: React.FC = () => {
  const { user, logout, isLoading, signinRedirect } = useAuth();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  useEffect(() => {
    if (!isLoading && !user) signinRedirect();
  }, [user, isLoading, signinRedirect]);

  if (isLoading || !user) {
    return (
      <div className="min-h-dvh flex items-center justify-center bg-zinc-950">
        <Spinner />
      </div>
    );
  }

  const initials = user.profile.preferred_username?.[0]?.toUpperCase() || 'U';
  const currentPage = navItems.find((n) => n.to === location.pathname)?.label || 'Account';

  return (
    <div className="min-h-dvh flex flex-col md:flex-row">
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-60 bg-zinc-950 flex flex-col',
          'transform transition-transform duration-200 ease-in-out md:translate-x-0 md:relative',
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="flex items-center justify-between px-5 h-16">
          <span className="text-white font-bold tracking-tight">Autentico</span>
          <button
            className="md:hidden text-zinc-500 hover:text-white"
            onClick={() => setMobileMenuOpen(false)}
          >
            <IconX size={18} />
          </button>
        </div>

        <nav className="flex-1 px-3 space-y-0.5 overflow-y-auto">
          {navItems.map((item) => (
            <SidebarItem
              key={item.to}
              to={item.to}
              icon={item.icon}
              label={item.label}
              active={location.pathname === item.to}
            />
          ))}
        </nav>

        <div className="px-3 py-4 border-t border-white/10 space-y-1">
          <div className="flex items-center gap-2.5 px-3 py-2.5">
            <div className="w-8 h-8 rounded-full bg-white/10 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
              {initials}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-white truncate leading-snug">
                {user.profile.preferred_username}
              </p>
              <p className="text-[11px] text-zinc-500 leading-snug">Personal account</p>
            </div>
          </div>
          <button
            onClick={() => logout()}
            className="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-zinc-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
          >
            <IconLogout size={15} />
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 flex flex-col min-w-0">
        <header className="h-16 bg-zinc-100 flex items-center gap-4 px-5 md:px-8">
          <button
            className="md:hidden text-zinc-400 hover:text-black"
            onClick={() => setMobileMenuOpen(true)}
          >
            <IconMenu2 size={20} />
          </button>
          <h1 className="text-xl font-bold tracking-tight">{currentPage}</h1>
        </header>

        <div className="p-5 md:p-8 max-w-3xl">
          <Suspense
            fallback={
              <div className="flex justify-center pt-16">
                <div className="w-6 h-6 border-2 border-zinc-300 border-t-zinc-900 rounded-full animate-spin" />
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

      {/* Mobile bottom nav trigger */}
      <div className="fixed bottom-4 right-4 md:hidden">
        <button
          onClick={() => setMobileMenuOpen(true)}
          className="w-12 h-12 bg-zinc-900 text-white rounded-full shadow-lg flex items-center justify-center"
        >
          <IconMenu2 size={20} />
        </button>
      </div>
    </div>
  );
};

export default Layout;
