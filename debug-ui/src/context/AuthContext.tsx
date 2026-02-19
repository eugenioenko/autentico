import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import { UserManager, type User } from "oidc-client-ts";

const AUTHORITY = "http://localhost:9999/oauth2";
const CLIENT_ID = "autentico-debug";
const REDIRECT_URI = "http://localhost:5174/callback";

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  startLogin: () => Promise<void>;
  handleCallback: () => Promise<void>;
  logout: () => Promise<void>;
  renewToken: () => Promise<User | null>;
}

const AuthContext = createContext<AuthContextType | null>(null);

function createUserManager() {
  return new UserManager({
    authority: AUTHORITY,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email offline_access",
    automaticSilentRenew: true,
    loadUserInfo: true,
    post_logout_redirect_uri: "http://localhost:5174/login",
  });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const userManagerRef = useRef(createUserManager());
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const mgr = userManagerRef.current;
    
    const onUserLoaded = (u: User) => {
      setUser(u);
      setIsAuthenticated(true);
    };

    const onUserUnloaded = () => {
      setUser(null);
      setIsAuthenticated(false);
    };

    mgr.events.addUserLoaded(onUserLoaded);
    mgr.events.addUserUnloaded(onUserUnloaded);

    mgr.getUser().then((u) => {
      if (u && !u.expired) {
        setUser(u);
        setIsAuthenticated(true);
      }
      setInitialized(true);
    });

    return () => {
      mgr.events.removeUserLoaded(onUserLoaded);
      mgr.events.removeUserUnloaded(onUserUnloaded);
    };
  }, []);

  const startLogin = useCallback(async () => {
    await userManagerRef.current.signinRedirect();
  }, []);

  const handleCallback = useCallback(async () => {
    const u = await userManagerRef.current.signinCallback();
    if (!u) {
      throw new Error("Sign-in failed: no user returned");
    }
    // Note: mgr.events.addUserLoaded will also trigger and update state
    setUser(u);
    setIsAuthenticated(true);
  }, []);

  const logout = useCallback(async () => {
    await userManagerRef.current.removeUser();
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  const renewToken = useCallback(async () => {
    try {
      const u = await userManagerRef.current.signinSilent();
      setUser(u);
      return u;
    } catch (err) {
      console.error("Silent renew failed", err);
      return null;
    }
  }, []);

  if (!initialized) {
    return null;
  }

  return (
    <AuthContext.Provider
      value={{ isAuthenticated, user, startLogin, handleCallback, logout, renewToken }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
