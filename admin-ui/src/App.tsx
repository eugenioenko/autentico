import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import AdminLayout from "./layouts/AdminLayout";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const CallbackPage = lazy(() => import("./pages/CallbackPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const ClientsPage = lazy(() => import("./pages/ClientsPage"));
const UsersPage = lazy(() => import("./pages/UsersPage"));
const SessionsPage = lazy(() => import("./pages/SessionsPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const FederationPage = lazy(() => import("./pages/FederationPage"));

const queryClient = new QueryClient();

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
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
                <Route path="sessions" element={<SessionsPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="federation" element={<FederationPage />} />
              </Route>
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
