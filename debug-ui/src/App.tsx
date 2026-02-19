import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConfigProvider } from "antd";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import LoginPage from "./pages/LoginPage";
import CallbackPage from "./pages/CallbackPage";
import DashboardPage from "./pages/DashboardPage";

const queryClient = new QueryClient();

export default function App() {
  return (
    <ConfigProvider theme={{
      token: {
        colorPrimary: '#fa541c', // A different color for debug UI (Orange-red)
      },
    }}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/callback" element={<CallbackPage />} />
              <Route element={<ProtectedRoute />}>
                <Route index element={<DashboardPage />} />
              </Route>
            </Routes>
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ConfigProvider>
  );
}
