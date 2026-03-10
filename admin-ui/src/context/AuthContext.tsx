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
}

const AuthContext = createContext<AuthContextType | null>(null);

function createUserManager() {
  return new UserManager({
    authority: window.location.origin,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email",
    automaticSilentRenew: false,
    loadUserInfo: false,
  });
}

const OAUTH_PATH = "/oauth2";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [userManager, setMgr] = useState<UserManager | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const mgr = createUserManager();
    setMgr(mgr);
    setUserManager(mgr);
    mgr.getUser().then((u) => {
      if (u && !u.expired) {
        setUser(u);
        setIsAuthenticated(true);
      }
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
      await apiClient.get("/admin/api/clients", {
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
  }, [userManager]);

  const logout = useCallback(async () => {
    if (!userManager) return;
    const currentUser = await userManager.getUser();
    if (currentUser?.access_token) {
      try {
        await apiClient.post(OAUTH_PATH + "/logout", null, {
          headers: { Authorization: `Bearer ${currentUser.access_token}` },
        });
      } catch {
        // Ignore logout errors
      }
    }
    await userManager.removeUser();
    setUser(null);
    setIsAuthenticated(false);
  }, [userManager]);

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
