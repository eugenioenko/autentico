import React, { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react';
import { UserManager, type User } from 'oidc-client-ts';
import { setUserManager } from './api';

const CLIENT_ID = 'autentico-account';
const REDIRECT_URI = window.location.origin + '/account/callback';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  signinRedirect: () => Promise<void>;
  signinCallback: () => Promise<void>;
  signoutRedirect: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function createUserManager(authority: string) {
  return new UserManager({
    authority,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    post_logout_redirect_uri: window.location.origin + '/account/',
    response_type: 'code',
    scope: 'openid profile email offline_access',
    automaticSilentRenew: true,
    filterProtocolClaims: true,
    loadUserInfo: true,
  });
}

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [userManager, setMgr] = useState<UserManager | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch('/account/api/settings')
      .then((r) => r.json())
      .then((res: { data: { oauth_path: string } }) => {
        const authority = window.location.origin + res.data.oauth_path;
        const mgr = createUserManager(authority);
        setMgr(mgr);
        setUserManager(mgr);
        return mgr.getUser();
      })
      .then((u) => {
        if (u && !u.expired) setUser(u);
        setIsLoading(false);
      })
      .catch(() => {
        const mgr = createUserManager(window.location.origin + '/oauth2');
        setMgr(mgr);
        setUserManager(mgr);
        setIsLoading(false);
      });
  }, []);

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

  const signoutRedirect = useCallback(async () => {
    if (userManager) await userManager.signoutRedirect();
  }, [userManager]);

  return (
    <AuthContext.Provider value={{ user, isLoading, signinRedirect, signinCallback, signoutRedirect }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};
