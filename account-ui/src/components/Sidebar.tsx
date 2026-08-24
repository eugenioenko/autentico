import React from 'react';
import { useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  IconUser, IconShield, IconKey, IconHistory, IconLogout,
  IconX, IconDevices, IconLink,
} from '@tabler/icons-react';
import { cn } from '../lib/utils';
import SidebarItem from './SidebarItem';
import LanguageSwitcher from './LanguageSwitcher';
import { useSettings } from '../context/SettingsContext';

function useNavItems() {
  const { t } = useTranslation();
  return [
    { to: '/', icon: IconShield, label: t('menu.overview') },
    { to: '/profile', icon: IconUser, label: t('menu.profile') },
    { to: '/security', icon: IconKey, label: t('menu.security') },
    { to: '/sessions', icon: IconHistory, label: t('menu.sessions') },
    { to: '/trusted-devices', icon: IconDevices, label: t('menu.trustedDevices') },
    { to: '/connected-providers', icon: IconLink, label: t('menu.connectedProviders') },
  ];
}

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
  const { t } = useTranslation();
  const navItems = useNavItems();

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
          <img
            src={settings.theme_logo_url || '/account/favicon.svg'}
            alt={settings.theme_title}
            className="h-6 w-6 object-contain"
          />
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
        <div className="px-1 pb-2">
          <LanguageSwitcher />
        </div>
        <div className="flex items-center gap-2.5 px-3 py-2.5">
          <div className="w-8 h-8 rounded-full bg-theme-accent-fg flex items-center justify-center text-theme-accent-bg text-xs font-bold flex-shrink-0">
            {initials}
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-theme-accent-fg truncate leading-snug">
              {username}
            </p>
            <p className="text-[11px] text-theme-accent-fg/40 leading-snug">{t('menu.personalAccount')}</p>
          </div>
        </div>
        <button
          onClick={onLogout}
          data-testid="sign-out"
          className="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-theme-accent-fg/70 hover:text-theme-accent-fg hover:bg-theme-accent-fg/10 rounded-brand transition-colors"
        >
          <IconLogout size={15} />
          {t('menu.signOut')}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
