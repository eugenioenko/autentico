import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";

const AUTHORITY = "http://localhost:9999/oauth2";
const CLIENT_ID = "autentico-debug";
const REDIRECT_URI = "http://localhost:5174/callback";
const POST_LOGOUT_REDIRECT_URI = "http://localhost:5174/login";
const SCOPES = "openid profile email offline_access";
const STORAGE_KEY = "autentico_debug_tokens";

interface TokenSet {
  access_token: string;
  refresh_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

// Minimal user-like shape consumed by the dashboard.
export interface DebugUser {
  access_token: string;
  refresh_token: string;
  id_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  expires_at: number;
  expired: boolean;
  profile: Record<string, unknown>;
}

interface AuthContextType {
  isAuthenticated: boolean;
  user: DebugUser | null;
  startLogin: () => Promise<void>;
  handleCallback: () => Promise<void>;
  logout: () => Promise<void>;
  renewToken: () => Promise<DebugUser | null>;
}

const AuthContext = createContext<AuthContextType | null>(null);

function parseJwtPayload(token: string): Record<string, unknown> {
  try {
    const base64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(base64));
  } catch {
    return {};
  }
}

function buildUser(tokens: TokenSet): DebugUser {
  const expiresAt = Math.floor(Date.now() / 1000) + tokens.expires_in;
  const profile = tokens.id_token ? parseJwtPayload(tokens.id_token) : {};
  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    token_type: tokens.token_type,
    scope: tokens.scope,
    expires_in: tokens.expires_in,
    expires_at: expiresAt,
    expired: expiresAt <= Math.floor(Date.now() / 1000),
    profile,
  };
}

function saveTokens(tokens: TokenSet) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(tokens));
}

function loadTokens(): TokenSet | null {
  const raw = sessionStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function clearTokens() {
  sessionStorage.removeItem(STORAGE_KEY);
}

// Generate a random string for PKCE and state.
function randomString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, length);
}

// PKCE S256: BASE64URL(SHA256(verifier))
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<DebugUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [initialized, setInitialized] = useState(false);

  // Restore from session storage on mount.
  useEffect(() => {
    const tokens = loadTokens();
    if (tokens) {
      const u = buildUser(tokens);
      setUser(u);
      setIsAuthenticated(true);
    }
    setInitialized(true);
  }, []);

  const startLogin = useCallback(async () => {
    const state = randomString(32);
    const codeVerifier = randomString(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Store PKCE verifier and state for callback.
    sessionStorage.setItem("oidc_state", state);
    sessionStorage.setItem("oidc_code_verifier", codeVerifier);

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

    window.location.href = `${AUTHORITY}/authorize?${params}`;
  }, []);

  const handleCallback = useCallback(async () => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const returnedState = params.get("state");
    const savedState = sessionStorage.getItem("oidc_state");
    const codeVerifier = sessionStorage.getItem("oidc_code_verifier");

    sessionStorage.removeItem("oidc_state");
    sessionStorage.removeItem("oidc_code_verifier");

    if (!code) throw new Error("No authorization code in callback URL");
    if (returnedState !== savedState) throw new Error("State mismatch");
    if (!codeVerifier) throw new Error("Missing PKCE code_verifier");

    const resp = await fetch(`${AUTHORITY}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: codeVerifier,
      }),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Token exchange failed (${resp.status}): ${text}`);
    }

    const tokens: TokenSet = await resp.json();
    saveTokens(tokens);
    const u = buildUser(tokens);
    setUser(u);
    setIsAuthenticated(true);
  }, []);

  const logout = useCallback(async () => {
    clearTokens();
    setUser(null);
    setIsAuthenticated(false);
    window.location.href = POST_LOGOUT_REDIRECT_URI;
  }, []);

  const renewToken = useCallback(async () => {
    const tokens = loadTokens();
    if (!tokens?.refresh_token) {
      console.error("No refresh token available");
      return null;
    }

    try {
      const resp = await fetch(`${AUTHORITY}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token,
          client_id: CLIENT_ID,
        }),
      });

      if (!resp.ok) {
        const text = await resp.text();
        console.error(`Refresh failed (${resp.status}): ${text}`);
        return null;
      }

      const newTokens: TokenSet = await resp.json();
      saveTokens(newTokens);
      const u = buildUser(newTokens);
      setUser(u);
      return u;
    } catch (err) {
      console.error("Silent renew failed", err);
      return null;
    }
  }, []);

  if (!initialized) return null;

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
