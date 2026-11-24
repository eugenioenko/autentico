import React, { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

import Spinner from '../components/Spinner';

export interface Settings {
  theme_logo_url: string;
  theme_title: string;
  auth_mode: string;
  require_mfa: boolean;
  mfa_method: string;
  oauth_path: string;
  allow_username_change: boolean;
  allow_email_change: boolean;
  allow_self_service_deletion: boolean;
  profile_field_given_name: string;
  profile_field_family_name: string;
  profile_field_middle_name: string;
  profile_field_nickname: string;
  profile_field_phone: string;
  profile_field_picture: string;
  profile_field_website: string;
  profile_field_gender: string;
  profile_field_birthdate: string;
  profile_field_profile: string;
  profile_field_locale: string;
  profile_field_address: string;
}

const defaultSettings: Settings = {
  theme_logo_url: '',
  theme_title: 'Autentico',
  auth_mode: 'password',
  require_mfa: false,
  mfa_method: 'totp',
  oauth_path: '/oauth2',
  allow_username_change: false,
  allow_email_change: false,
  allow_self_service_deletion: false,
  profile_field_given_name: 'optional',
  profile_field_family_name: 'optional',
  profile_field_middle_name: 'hidden',
  profile_field_nickname: 'hidden',
  profile_field_phone: 'optional',
  profile_field_picture: 'optional',
  profile_field_website: 'hidden',
  profile_field_gender: 'hidden',
  profile_field_birthdate: 'hidden',
  profile_field_profile: 'hidden',
  profile_field_address: 'optional',
  profile_field_locale: 'hidden',
};

const SettingsContext = createContext<Settings>(defaultSettings);

export const SettingsProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetch('/account/api/settings', { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error('Could not load account settings');
        return r.json();
      })
      .then((res: { data: Settings }) => {
        if (typeof res.data?.oauth_path !== 'string') throw new Error('Missing OAuth path');
        const merged = { ...defaultSettings, ...res.data };
        setSettings(merged);
        if (merged.theme_logo_url) {
          const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
          if (link) link.href = merged.theme_logo_url;
        }
      })
      .catch(() => { if (!controller.signal.aborted) setLoadFailed(true); });
    return () => controller.abort();
  }, []);

  if (loadFailed) return <div role="alert">Could not load account settings. <button onClick={() => window.location.reload()}>Retry</button></div>;
  // Mount the OIDC provider only after the server supplies its issuer path.
  if (!settings) return <Spinner />;
  return <SettingsContext.Provider value={settings}>{children}</SettingsContext.Provider>;
};

export const useSettings = () => useContext(SettingsContext);
