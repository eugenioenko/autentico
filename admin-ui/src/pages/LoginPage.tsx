import { useEffect } from "react";
import { useSearchParams, Navigate } from "react-router-dom";
import { Alert, Button, Spinner, Stack, Text } from "@yarcl/react";
import { useAuth } from "oidc-js-react";
import "./AuthScreen.css";

export default function LoginPage() {
  const { isAuthenticated, actions } = useAuth();
  const [searchParams] = useSearchParams();
  const errorParam = searchParams.get("error");

  useEffect(() => {
    if (isAuthenticated || errorParam) return;
    actions.login();
  }, [isAuthenticated, errorParam, actions]);

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="auth-screen">
      {errorParam ? (
        <Stack gap="lg" align="center" className="auth-screen-content">
          <Alert color="danger" title="Authentication Failed">
            {decodeURIComponent(errorParam)}
          </Alert>
          <Button variant="ghost" onClick={() => actions.login()}>
            Try again
          </Button>
        </Stack>
      ) : (
        <Stack gap="sm" align="center">
          <Spinner size="lg" label="Redirecting to login..." />
          <Text muted>Redirecting to login...</Text>
        </Stack>
      )}
    </div>
  );
}
