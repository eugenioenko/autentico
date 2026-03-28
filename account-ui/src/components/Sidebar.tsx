import React from 'react';
import { useLocation } from 'react-router-dom';
import {
  IconUser, IconShield, IconKey, IconHistory, IconLogout,
  IconX, IconDevices, IconLink,
} from '@tabler/icons-react';
import { cn } from '../lib/utils';
import SidebarItem from './SidebarItem';

const navItems = [
  { to: '/', icon: IconShield, label: 'Overview' },
  { to: '/profile', icon: IconUser, label: 'Profile' },
  { to: '/security', icon: IconKey, label: 'Security' },
  { to: '/sessions', icon: IconHistory, label: 'Sessions' },
  { to: '/trusted-devices', icon: IconDevices, label: 'Trusted Devices' },
  { to: '/connected-providers', icon: IconLink, label: 'Connected Providers' },
];

interface SidebarProps {
  open: boolean;
  onClose: () => void;
  username: string;
  initials: string;
  appName: string;
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ open, onClose, username, initials, appName, onLogout }) => {
  const location = useLocation();

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-50 w-60 bg-theme-accent-bg flex flex-col',
        'transform transition-transform duration-200 ease-in-out md:translate-x-0 md:relative',
        open ? 'translate-x-0' : '-translate-x-full'
      )}
    >
      <div className="flex items-center justify-between px-5 h-16">
        <span className="text-theme-accent-fg font-bold tracking-tight">{appName}</span>
        <button
          className="md:hidden text-theme-accent-fg/70 hover:text-theme-accent-fg"
          onClick={onClose}
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

      <div className="px-3 py-4 border-t border-theme-accent-fg/30 space-y-1">
        <div className="flex items-center gap-2.5 px-3 py-2.5">
          <div className="w-8 h-8 rounded-full bg-theme-accent-fg flex items-center justify-center text-theme-accent-bg text-xs font-bold flex-shrink-0">
            {initials}
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-theme-accent-fg truncate leading-snug">
              {username}
            </p>
            <p className="text-[11px] text-theme-accent-fg/40 leading-snug">Personal account</p>
          </div>
        </div>
        <button
          onClick={onLogout}
          className="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-theme-accent-fg/70 hover:text-theme-accent-fg hover:bg-theme-primary-bg rounded-brand transition-colors"
        >
          <IconLogout size={15} />
          Sign out
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
