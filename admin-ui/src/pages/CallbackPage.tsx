import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Spinner, Stack, Text } from "@yarcl/react";
import { useAuth } from "oidc-js-react";
import apiClient from "../api/client";
import "./AuthScreen.css";

export default function CallbackPage() {
  const navigate = useNavigate();
  const { isAuthenticated, isLoading, tokens } = useAuth();
  const processed = useRef(false);

  useEffect(() => {
    if (isLoading || processed.current) return;
    processed.current = true;

    if (!isAuthenticated) {
      navigate("/login?error=Sign-in+failed", { replace: true });
      return;
    }

    apiClient
      .get("/admin/api/clients", {
        headers: { Authorization: `Bearer ${tokens.access}` },
      })
      .then(() => {
        // onLogin handles navigation to returnTo
      })
      .catch((err: unknown) => {
        const status =
          err && typeof err === "object" && "response" in err
            ? (err as { response?: { status?: number } }).response?.status
            : undefined;
        const msg =
          status === 403
            ? "Admin access required"
            : "Failed to verify admin access";
        navigate(`/login?error=${encodeURIComponent(msg)}`, { replace: true });
      });
  }, [isAuthenticated, isLoading, tokens, navigate]);

  return (
    <div className="auth-screen">
      <Stack gap="sm" align="center">
        <Spinner size="lg" label="Signing in..." />
        <Text muted>Signing in...</Text>
      </Stack>
    </div>
  );
}
