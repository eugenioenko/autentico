import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App, ConfigProvider, theme } from "antd";
import { AuthProvider } from "./context/AuthContext";
import { ThemeProvider, useTheme } from "./context/ThemeContext";
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
const AuditLogPage = lazy(() => import("./pages/AuditLogPage"));

const queryClient = new QueryClient();

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
        <BrowserRouter basename="/admin">
          <AuthProvider>
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
                  <Route path="settings" element={<SettingsPage />} />
                  <Route path="cors" element={<CorsPage />} />
                  <Route path="federation" element={<FederationPage />} />
                  <Route path="audit-log" element={<AuditLogPage />} />
                </Route>
              </Route>
            </Routes>
          </AuthProvider>
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
