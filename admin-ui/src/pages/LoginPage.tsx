import { useEffect } from "react";
import { useSearchParams, Navigate } from "react-router-dom";
import { Alert, Spin, Space, Typography } from "antd";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const { startLogin, isAuthenticated } = useAuth();
  const [searchParams] = useSearchParams();
  const errorParam = searchParams.get("error");

  useEffect(() => {
    if (!isAuthenticated && !errorParam) {
      startLogin();
    }
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
      ) : (
        <Spin size="large" tip="Redirecting to login..." />
      )}
    </div>
  );
}
