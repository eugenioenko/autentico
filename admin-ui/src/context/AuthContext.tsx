import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";
import { UserManager, type User } from "oidc-client-ts";
import apiClient from "../api/client";
import { setUserManager } from "../api/client";

const CLIENT_ID = "autentico-admin";
const REDIRECT_URI = window.location.origin + "/admin/callback";

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  startLogin: (extraQueryParams?: Record<string, string>) => Promise<void>;
  handleCallback: () => Promise<void>;
  logout: () => Promise<void>;
  oauthPath: string;
}

const AuthContext = createContext<AuthContextType | null>(null);

function createUserManager(authority: string) {
  return new UserManager({
    authority: authority,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email",
    automaticSilentRenew: false,
    loadUserInfo: false,
  });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [userManager, setMgr] = useState<UserManager | null>(null);
  const [oauthPath, setOauthPath] = useState("");
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    fetch("/admin/api/onboarding")
      .then((r) => r.json())
      .then((data: { onboarded: boolean; oauth_path: string }) => {
        const authority = window.location.origin + data.oauth_path;
        const mgr = createUserManager(authority);
        setMgr(mgr);
        setOauthPath(data.oauth_path);
        setUserManager(mgr);
        return mgr.getUser();
      })
      .then((u) => {
        if (u && !u.expired) {
          setUser(u);
          setIsAuthenticated(true);
        }
        setInitialized(true);
      })
      .catch(() => {
        // Fallback to default /oauth2 if onboarding check fails
        const authority = window.location.origin + "/oauth2";
        const mgr = createUserManager(authority);
        setMgr(mgr);
        setOauthPath("/oauth2");
        setUserManager(mgr);
        setInitialized(true);
      });
  }, []);

  const startLogin = useCallback(async (extraQueryParams?: Record<string, string>) => {
    if (userManager) await userManager.signinRedirect({ extraQueryParams });
  }, [userManager]);

  const handleCallback = useCallback(async () => {
    if (!userManager) return;
    const u = await userManager.signinCallback();
    if (!u) {
      throw new Error("Sign-in failed: no user returned");
    }

    // Verify admin access
    try {
      await apiClient.get(oauthPath + "/register", {
        headers: { Authorization: `Bearer ${u.access_token}` },
      });
    } catch (err: unknown) {
      await userManager.removeUser();
      const status =
        err && typeof err === "object" && "response" in err
          ? (err as { response?: { status?: number } }).response?.status
          : undefined;
      if (status === 403) {
        throw new Error("Admin access required");
      }
      throw new Error("Failed to verify admin access");
    }

    setUser(u);
    setIsAuthenticated(true);
  }, [userManager, oauthPath]);

  const logout = useCallback(async () => {
    if (!userManager) return;
    const currentUser = await userManager.getUser();
    if (currentUser?.access_token) {
      try {
        await apiClient.post(oauthPath + "/logout", null, {
          headers: { Authorization: `Bearer ${currentUser.access_token}` },
        });
      } catch {
        // Ignore logout errors
      }
    }
    await userManager.removeUser();
    setUser(null);
    setIsAuthenticated(false);
  }, [userManager, oauthPath]);

  if (!initialized) {
    return null;
  }

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        user,
        startLogin,
        handleCallback,
        logout,
        oauthPath,
      }}
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
