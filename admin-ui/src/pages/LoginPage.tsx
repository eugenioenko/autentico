import { useEffect, useState } from "react";
import { useSearchParams, Navigate } from "react-router-dom";
import { Alert, Spin, Space, Typography } from "antd";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const { startLogin, isAuthenticated } = useAuth();
  const [searchParams] = useSearchParams();
  const errorParam = searchParams.get("error");
  const [onboardingChecked, setOnboardingChecked] = useState(false);

  useEffect(() => {
    if (isAuthenticated || errorParam) {
      setOnboardingChecked(true);
      return;
    }

    fetch("/admin/api/onboarding")
      .then((r) => r.json())
      .then((data: { onboarded: boolean; oauth_path: string }) => {
        if (!data.onboarded) {
          // First time setup — start OIDC flow with prompt=signup
          startLogin({ prompt: "signup" });
        } else {
          setOnboardingChecked(true);
          startLogin();
        }
      })
      .catch(() => {
        // On error, fall through to normal login
        setOnboardingChecked(true);
        startLogin();
      });
  }, [isAuthenticated, errorParam, startLogin]);

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        background: "#f0f2f5",
      }}
    >
      {errorParam ? (
        <Space direction="vertical" align="center" size="large">
          <Alert
            message="Authentication Failed"
            description={decodeURIComponent(errorParam)}
            type="error"
            showIcon
          />
          <Typography.Link onClick={() => startLogin()}>
            Try again
          </Typography.Link>
        </Space>
      ) : onboardingChecked ? (
        <Spin size="large" tip="Redirecting to login..." />
      ) : (
        <Spin size="large" tip="Loading..." />
      )}
    </div>
  );
}
