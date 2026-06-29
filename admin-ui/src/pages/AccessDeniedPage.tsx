import { Button, Result, ConfigProvider, theme } from "antd";

export default function AccessDeniedPage() {
  return (
    <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm }}>
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          minHeight: "100vh",
          background: "#f0f2f5",
        }}
      >
        <Result
          status="403"
          title="未授权"
          subTitle="您的账户没有管理员权限。"
          extra={
            <Button type="primary" href="/account/">
              前往账户门户
            </Button>
          }
        />
      </div>
    </ConfigProvider>
  );
}
