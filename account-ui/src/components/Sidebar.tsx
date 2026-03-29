import React from 'react';
import { useLocation } from 'react-router-dom';
import {
  IconUser, IconShield, IconKey, IconHistory, IconLogout,
  IconX, IconDevices, IconLink,
} from '@tabler/icons-react';
import { cn } from '../lib/utils';
import SidebarItem from './SidebarItem';
import { useSettings } from '../context/SettingsContext';

const DefaultLogo: React.FC = () => (
  <svg fill="#ff7b00" width="24" height="24" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" transform="matrix(-1,0,0,1,0,0)">
    <rect x="40" y="40" width="440" height="440" fill="#ffffff" rx="30" ry="30" />
    <path d="M454,31H58A26.9635,26.9635,0,0,0,31,58V454a27.02,27.02,0,0,0,27,27H454a27.0225,27.0225,0,0,0,27-27V58A26.9663,26.9663,0,0,0,454,31ZM225.0361,116.0507a118.1831,118.1831,0,0,1,148.86,113.85,9.8987,9.8987,0,1,1-19.7974,0A98.215,98.215,0,0,0,256,131.8007a96.0267,96.0267,0,0,0-25.8311,3.42,9.9226,9.9226,0,0,1-5.1328-19.17ZM256,166a64.1092,64.1092,0,0,1,29.6982,7.2905,9.9028,9.9028,0,0,1-9.18,17.55A42.7651,42.7651,0,0,0,256,185.8007a44.116,44.116,0,0,0-44.1035,44.1V249.61a9.8987,9.8987,0,1,1-19.7974,0V229.9009A63.9722,63.9722,0,0,1,256,166Zm-65.9707-22.23a9.9507,9.9507,0,0,1-.5405,14.0405,98.1588,98.1588,0,0,0-31.5923,72.09v54a9.8987,9.8987,0,1,1-19.7974,0v-54a118.19,118.19,0,0,1,37.982-86.67A9.8386,9.8386,0,0,1,190.0293,143.77ZM57.0991,67A9.87,9.87,0,0,1,67,57.1013h72a9.9,9.9,0,0,1,0,19.8H76.8965V139a9.8987,9.8987,0,1,1-19.7974,0ZM139,454.9009H67A9.87,9.87,0,0,1,57.0991,445V373a9.8987,9.8987,0,1,1,19.7974,0v62.1013H139a9.9,9.9,0,0,1,0,19.8ZM168.7861,343.75a9.809,9.809,0,0,1-6.9257,2.8806,9.9,9.9,0,0,1-7.0225-16.92l19.71-19.62a66.3634,66.3634,0,0,0,8.82-11.25,9.88,9.88,0,0,1,16.831,10.3513A77.29,77.29,0,0,1,188.5,324.0405Zm37.4414,38.9707a9.8963,9.8963,0,0,1-14.04-13.95L212.71,348.25a113.42,113.42,0,0,0,33.39-80.64v-37.71a9.8987,9.8987,0,1,1,19.7974,0v37.71a132.7393,132.7393,0,0,1-39.2388,94.59Zm53.2793,18.99a9.72,9.72,0,0,1-6.9257-2.7895,9.86,9.86,0,0,1-.1846-14.0405,166.8562,166.8562,0,0,0,47.7026-117.27v-37.71a9.8987,9.8987,0,1,1,19.7974,0v37.71A186.4813,186.4813,0,0,1,266.5293,398.741,9.7472,9.7472,0,0,1,259.5068,401.7106Zm74.5225-29.43a9.7161,9.7161,0,0,1-6.57,2.52,9.94,9.94,0,0,1-6.57-17.37,98.0227,98.0227,0,0,0,33.21-73.5293,9.8987,9.8987,0,1,1,19.7974,0A118.25,118.25,0,0,1,334.0293,372.28ZM454.8965,445A9.8694,9.8694,0,0,1,445,454.9009H373a9.9,9.9,0,1,1,0-19.8h62.0991V373a9.8987,9.8987,0,1,1,19.7974,0Zm0-306a9.8987,9.8987,0,1,1-19.7974,0V76.9009H373a9.9,9.9,0,1,1,0-19.8h72A9.8689,9.8689,0,0,1,454.8965,67Z" />
  </svg>
);

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
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ open, onClose, username, initials, onLogout }) => {
  const location = useLocation();
  const settings = useSettings();

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-50 w-60 bg-theme-accent-bg flex flex-col',
        'transform transition-transform duration-200 ease-in-out md:translate-x-0 md:relative',
        open ? 'translate-x-0' : '-translate-x-full'
      )}
    >
      <div className="flex items-center justify-between px-5 h-16">
        <div className="flex items-center gap-2">
          {settings.theme_logo_url ? (
            <img src={settings.theme_logo_url} alt="Logo" className="h-6 w-6 object-contain" />
          ) : (
            <DefaultLogo />
          )}
          <span className="text-theme-accent-fg font-bold tracking-tight">{settings.theme_title}</span>
        </div>
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
          className="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-theme-accent-fg/70 hover:text-theme-primary-fg hover:bg-theme-primary-bg rounded-brand transition-colors"
        >
          <IconLogout size={15} />
          Sign out
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
