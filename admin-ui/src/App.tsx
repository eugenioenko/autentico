import { lazy, Suspense, useMemo } from "react";
import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App, ConfigProvider, theme } from "antd";
import { AuthProvider } from "oidc-js-react";
import type { OidcConfig } from "oidc-js-react";
import { ThemeProvider, useTheme } from "./context/ThemeContext";
import AuthBridge from "./components/AuthBridge";
import ProtectedRoute from "./components/ProtectedRoute";
import AdminLayout from "./layouts/AdminLayout";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const CallbackPage = lazy(() => import("./pages/CallbackPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const ClientsPage = lazy(() => import("./pages/ClientsPage"));
const UsersPage = lazy(() => import("./pages/UsersPage"));
const SessionsPage = lazy(() => import("./pages/SessionsPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const CorsPage = lazy(() => import("./pages/CorsPage"));
const FederationPage = lazy(() => import("./pages/FederationPage"));
const GroupsPage = lazy(() => import("./pages/GroupsPage"));
const TokensPage = lazy(() => import("./pages/TokensPage"));
const AuditLogPage = lazy(() => import("./pages/AuditLogPage"));

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1 } },
});

const BASENAME = "/admin";

const oidcConfig: OidcConfig = {
  issuer: window.location.origin + "/oauth2",
  clientId: "autentico-admin",
  redirectUri: window.location.origin + BASENAME + "/callback",
  scopes: ["openid", "profile", "email"],
  expiryBuffer: 0,
};

function AuthWrapper({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();

  const onLogin = useMemo(() => (returnTo: string) => {
    const path = returnTo.startsWith(BASENAME)
      ? returnTo.slice(BASENAME.length) || "/"
      : returnTo;
    navigate(path, { replace: true });
  }, [navigate]);

  return (
    <AuthProvider config={oidcConfig} fetchProfile={false} onLogin={onLogin}>
      <AuthBridge />
      {children}
    </AuthProvider>
  );
}

function ThemedApp() {
  const { mode } = useTheme();
  return (
    <ConfigProvider
      theme={{
        algorithm: mode === "dark" ? theme.darkAlgorithm : theme.defaultAlgorithm,
        ...(mode === "dark" && {
          components: {
            Layout: { bodyBg: "#0f0f0f" },
          },
        }),
      }}
    >
      <App>
        <BrowserRouter basename={BASENAME}>
          <AuthWrapper>
            <Routes>
              <Route path="/login" element={<Suspense fallback={null}><LoginPage /></Suspense>} />
              <Route path="/callback" element={<Suspense fallback={null}><CallbackPage /></Suspense>} />
              <Route element={<ProtectedRoute />}>
                <Route element={<AdminLayout />}>
                  <Route index element={<DashboardPage />} />
                  <Route path="clients" element={<ClientsPage />} />
                  <Route path="users" element={<UsersPage />} />
                  <Route path="groups" element={<GroupsPage />} />
                  <Route path="sessions" element={<SessionsPage />} />
                  <Route path="tokens" element={<TokensPage />} />
                  <Route path="settings" element={<SettingsPage />} />
                  <Route path="cors" element={<CorsPage />} />
                  <Route path="federation" element={<FederationPage />} />
                  <Route path="audit-log" element={<AuditLogPage />} />
                </Route>
              </Route>
            </Routes>
          </AuthWrapper>
        </BrowserRouter>
      </App>
    </ConfigProvider>
  );
}

export default function AppRoot() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <ThemedApp />
      </ThemeProvider>
    </QueryClientProvider>
  );
}
