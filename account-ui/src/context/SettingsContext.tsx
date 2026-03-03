import React, { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

export interface Settings {
  auth_mode: string;
  require_mfa: boolean;
  mfa_method: string;
  oauth_path: string;
  allow_username_change: boolean;
  allow_email_change: boolean;
  profile_field_given_name: string;
  profile_field_family_name: string;
  profile_field_phone: string;
  profile_field_picture: string;
  profile_field_locale: string;
  profile_field_address: string;
}

const defaultSettings: Settings = {
  auth_mode: 'password',
  require_mfa: false,
  mfa_method: 'totp',
  oauth_path: '/oauth2',
  allow_username_change: false,
  allow_email_change: false,
  profile_field_given_name: 'optional',
  profile_field_family_name: 'optional',
  profile_field_phone: 'optional',
  profile_field_picture: 'optional',
  profile_field_locale: 'optional',
  profile_field_address: 'optional',
};

const SettingsContext = createContext<Settings>(defaultSettings);

export const SettingsProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [settings, setSettings] = useState<Settings>(defaultSettings);

  useEffect(() => {
    fetch('/account/api/settings')
      .then((r) => r.json())
      .then((res: { data: Settings }) => setSettings({ ...defaultSettings, ...res.data }))
      .catch(() => {});
  }, []);

  return <SettingsContext.Provider value={settings}>{children}</SettingsContext.Provider>;
};

export const useSettings = () => useContext(SettingsContext);
