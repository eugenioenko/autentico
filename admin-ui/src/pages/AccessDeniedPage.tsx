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
          title="Unauthorized"
          subTitle="Your account does not have administrator privileges."
          extra={
            <Button type="primary" href="/account/">
              Go to Account Portal
            </Button>
          }
        />
      </div>
    </ConfigProvider>
  );
}
