import { useEffect } from "react";
import { useSearchParams, Navigate } from "react-router-dom";
import { Alert, Spin, Space, Typography } from "antd";
import { useAuth } from "oidc-js-react";
import { useTranslation } from "react-i18next";

export default function LoginPage() {
  const { isAuthenticated, actions } = useAuth();
  const [searchParams] = useSearchParams();
  const errorParam = searchParams.get("error");
  const { t } = useTranslation();

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
            message={t("login.authFailed")}
            description={decodeURIComponent(errorParam)}
            type="error"
            showIcon
          />
          <Typography.Link onClick={() => actions.login()}>
            {t("login.tryAgain")}
          </Typography.Link>
        </Space>
      ) : (
        <Spin size="large" tip={t("login.redirecting")} />
      )}
    </div>
  );
}
