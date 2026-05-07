import { Outlet } from "react-router-dom";
import { RequireAuth } from "oidc-js-react";

export default function ProtectedRoute() {
  return (
    <RequireAuth>
      <Outlet />
    </RequireAuth>
  );
}
