import { useEffect } from "react";
import { useSearchParams, Navigate } from "react-router-dom";
import { Alert, Spin, Space, Typography } from "antd";
import { useAuth } from "oidc-js-react";

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
          <Typography.Link onClick={() => actions.login()}>
            Try again
          </Typography.Link>
        </Space>
      ) : (
        <Spin size="large" tip="Redirecting to login..." />
      )}
    </div>
  );
}
