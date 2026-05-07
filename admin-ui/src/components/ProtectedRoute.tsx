import { useEffect } from "react";
import { Outlet } from "react-router-dom";
import { useAuth } from "oidc-js-react";

export default function ProtectedRoute() {
  const { isAuthenticated, isLoading, actions } = useAuth();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      actions.login();
    }
  }, [isLoading, isAuthenticated, actions]);

  if (!isAuthenticated) {
    return null;
  }

  return <Outlet />;
}
