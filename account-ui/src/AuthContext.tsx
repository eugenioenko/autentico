import React, { createContext, useContext, useEffect, useRef, useState, useCallback, type ReactNode } from 'react';
import { UserManager, type User } from 'oidc-client-ts';
import { setUserManager } from './api';
import { useSettings } from './context/SettingsContext';

const CLIENT_ID = 'autentico-account';
const REDIRECT_URI = window.location.origin + '/account/callback';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  signinRedirect: () => Promise<void>;
  signinCallback: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function createUserManager(authority: string) {
  return new UserManager({
    authority,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid profile email offline_access',
    automaticSilentRenew: true,
    filterProtocolClaims: true,
    loadUserInfo: true,
  });
}

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { oauth_path } = useSettings();
  const [userManager, setMgr] = useState<UserManager | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    async function init() {
      const authority = window.location.origin + oauth_path;
      const mgr = createUserManager(authority);
      setMgr(mgr);
      setUserManager(mgr);

      try {
        const stored = await mgr.getUser();
        if (stored) {
          // Refresh the stored session (uses refresh token via token endpoint, no redirect)
          const u = await mgr.signinSilent();
          setUser(u ?? null);
        } else {
          // No stored session — skip silent renew, Layout will call signinRedirect()
          setUser(null);
        }
      } catch {
        await mgr.removeUser();
        setUser(null);
      }

      setIsLoading(false);
    }

    init();
  }, [oauth_path]);

  useEffect(() => {
    if (!userManager) return;
    const onLoaded = (u: User) => setUser(u);
    const onUnloaded = () => setUser(null);
    userManager.events.addUserLoaded(onLoaded);
    userManager.events.addUserUnloaded(onUnloaded);
    return () => {
      userManager.events.removeUserLoaded(onLoaded);
      userManager.events.removeUserUnloaded(onUnloaded);
    };
  }, [userManager]);

  const signinRedirect = useCallback(async () => {
    if (userManager) await userManager.signinRedirect();
  }, [userManager]);

  const signinCallback = useCallback(async () => {
    if (!userManager) return;
    await userManager.signinCallback();
    const u = await userManager.getUser();
    setUser(u);
  }, [userManager]);

  const logout = useCallback(async () => {
    if (!userManager) return;
    const currentUser = await userManager.getUser();
    if (currentUser?.access_token) {
      try {
        await fetch(window.location.origin + oauth_path + '/logout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${currentUser.access_token}`,
          },
        });
      } catch (err) {
        console.error('Logout failed', err);
      }
    }
    await userManager.removeUser();
    setUser(null);
  }, [userManager, oauth_path]);

  return (
    <AuthContext.Provider value={{ user, isLoading, signinRedirect, signinCallback, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};
