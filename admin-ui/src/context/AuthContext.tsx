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
import apiClient from "../api/client";
import { setUserManager } from "../api/client";

const AUTHORITY = window.location.origin + "/oauth2";
const CLIENT_ID = "autentico-admin";
const REDIRECT_URI = window.location.origin + "/admin/callback";

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  startLogin: () => Promise<void>;
  handleCallback: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

function createUserManager() {
  return new UserManager({
    authority: AUTHORITY,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email",
    automaticSilentRenew: false,
    loadUserInfo: false,
  });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const userManagerRef = useRef(createUserManager());
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const mgr = userManagerRef.current;
    setUserManager(mgr);
    mgr.getUser().then((u) => {
      if (u && !u.expired) {
        setUser(u);
        setIsAuthenticated(true);
      }
      setInitialized(true);
    });
  }, []);

  const startLogin = useCallback(async () => {
    await userManagerRef.current.signinRedirect();
  }, []);

  const handleCallback = useCallback(async () => {
    const u = await userManagerRef.current.signinCallback();
    if (!u) {
      throw new Error("Sign-in failed: no user returned");
    }

    // Verify admin access
    try {
      await apiClient.get("/oauth2/register", {
        headers: { Authorization: `Bearer ${u.access_token}` },
      });
    } catch (err: unknown) {
      await userManagerRef.current.removeUser();
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
  }, []);

  const logout = useCallback(async () => {
    const currentUser = await userManagerRef.current.getUser();
    if (currentUser?.access_token) {
      try {
        await apiClient.post("/oauth2/logout", null, {
          headers: { Authorization: `Bearer ${currentUser.access_token}` },
        });
      } catch {
        // Ignore logout errors
      }
    }
    await userManagerRef.current.removeUser();
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  if (!initialized) {
    return null;
  }

  return (
    <AuthContext.Provider
      value={{ isAuthenticated, user, startLogin, handleCallback, logout }}
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
