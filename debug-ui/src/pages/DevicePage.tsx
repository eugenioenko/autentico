import { useState, useEffect, useRef } from "react";
import { Button, Card, Typography, Space, Alert, Spin, Descriptions } from "antd";
import { MobileOutlined, CheckCircleOutlined, CloseCircleOutlined } from "@ant-design/icons";

const { Title, Text, Paragraph } = Typography;

const AUTHORITY = "/oauth2";
const CLIENT_ID = "autentico-debug";

interface DeviceAuthResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

type Status = "idle" | "polling" | "authorized" | "denied" | "expired" | "error";

export default function DevicePage() {
  const [status, setStatus] = useState<Status>("idle");
  const [deviceAuth, setDeviceAuth] = useState<DeviceAuthResponse | null>(null);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startDeviceFlow = async () => {
    setStatus("idle");
    setError(null);
    setTokens(null);
    setDeviceAuth(null);

    try {
      const resp = await fetch(`${AUTHORITY}/device_authorization`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          scope: "openid profile email",
        }),
      });

      if (!resp.ok) {
        const body = await resp.json();
        setError(body.error_description || body.error || "Failed to start device flow");
        setStatus("error");
        return;
      }

      const data: DeviceAuthResponse = await resp.json();
      setDeviceAuth(data);
      setSecondsLeft(data.expires_in);
      setStatus("polling");
      startPolling(data.device_code, data.interval);
      startCountdown(data.expires_in);
    } catch (err) {
      setError(String(err));
      setStatus("error");
    }
  };

  const startPolling = (deviceCode: string, interval: number) => {
    if (pollRef.current) clearInterval(pollRef.current);

    pollRef.current = setInterval(async () => {
      try {
        const resp = await fetch(`${AUTHORITY}/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: deviceCode,
            client_id: CLIENT_ID,
          }),
        });

        if (resp.ok) {
          const data: TokenResponse = await resp.json();
          setTokens(data);
          setStatus("authorized");
          stopPolling();
          return;
        }

        const body = await resp.json();
        switch (body.error) {
          case "authorization_pending":
            break;
          case "slow_down":
            // Back off by restarting with longer interval
            stopPolling();
            pollRef.current = setInterval(() => {
              startPolling(deviceCode, interval + 5);
            }, (interval + 5) * 1000);
            break;
          case "access_denied":
            setStatus("denied");
            stopPolling();
            break;
          case "expired_token":
            setStatus("expired");
            stopPolling();
            break;
          default:
            setError(body.error_description || body.error);
            setStatus("error");
            stopPolling();
        }
      } catch (err) {
        setError(String(err));
        setStatus("error");
        stopPolling();
      }
    }, interval * 1000);
  };

  const startCountdown = (seconds: number) => {
    if (countdownRef.current) clearInterval(countdownRef.current);
    let remaining = seconds;
    countdownRef.current = setInterval(() => {
      remaining--;
      setSecondsLeft(remaining);
      if (remaining <= 0) {
        if (countdownRef.current) clearInterval(countdownRef.current);
      }
    }, 1000);
  };

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    if (countdownRef.current) {
      clearInterval(countdownRef.current);
      countdownRef.current = null;
    }
  };

  useEffect(() => {
    return () => stopPolling();
  }, []);

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '100vh',
      backgroundColor: '#f0f2f5',
      padding: 24,
    }}>
      <Card style={{ width: 500, textAlign: 'center' }}>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Title level={2}><MobileOutlined /> Device Flow</Title>
          <Text type="secondary">Simulates a device (CLI/TV) requesting authorization</Text>

          {status === "idle" && (
            <Button type="primary" size="large" onClick={startDeviceFlow} block>
              Start Device Authorization
            </Button>
          )}

          {status === "polling" && deviceAuth && (
            <>
              <Alert
                message="Enter this code on the verification page"
                description={
                  <div>
                    <Paragraph copyable style={{ fontSize: 32, fontWeight: 'bold', letterSpacing: 4, margin: '16px 0' }}>
                      {deviceAuth.user_code}
                    </Paragraph>
                    <Text>Visit: <a href={deviceAuth.verification_uri_complete} target="_blank" rel="noopener noreferrer">
                      {deviceAuth.verification_uri}
                    </a></Text>
                  </div>
                }
                type="info"
              />
              <Space>
                <Spin size="small" />
                <Text type="secondary">Waiting for authorization... ({secondsLeft}s remaining)</Text>
              </Space>
              <Button onClick={() => { stopPolling(); setStatus("idle"); }}>Cancel</Button>
            </>
          )}

          {status === "authorized" && tokens && (
            <>
              <Alert
                message="Device Authorized"
                description="The user approved the device. Tokens received."
                type="success"
                icon={<CheckCircleOutlined />}
                showIcon
              />
              <Descriptions column={1} bordered size="small" style={{ textAlign: 'left' }}>
                <Descriptions.Item label="Access Token">
                  <Text code copyable style={{ wordBreak: 'break-all', fontSize: 11 }}>
                    {tokens.access_token.substring(0, 50)}...
                  </Text>
                </Descriptions.Item>
                <Descriptions.Item label="Refresh Token">
                  <Text code copyable style={{ wordBreak: 'break-all', fontSize: 11 }}>
                    {tokens.refresh_token.substring(0, 50)}...
                  </Text>
                </Descriptions.Item>
                <Descriptions.Item label="Scope">{tokens.scope}</Descriptions.Item>
                <Descriptions.Item label="Expires In">{tokens.expires_in}s</Descriptions.Item>
              </Descriptions>
              <Button type="primary" onClick={startDeviceFlow}>Start Again</Button>
            </>
          )}

          {status === "denied" && (
            <>
              <Alert
                message="Access Denied"
                description="The user denied the authorization request."
                type="error"
                icon={<CloseCircleOutlined />}
                showIcon
              />
              <Button type="primary" onClick={startDeviceFlow}>Try Again</Button>
            </>
          )}

          {status === "expired" && (
            <>
              <Alert
                message="Code Expired"
                description="The device code has expired. Please request a new one."
                type="warning"
              />
              <Button type="primary" onClick={startDeviceFlow}>Start Again</Button>
            </>
          )}

          {status === "error" && (
            <>
              <Alert message="Error" description={error} type="error" />
              <Button type="primary" onClick={startDeviceFlow}>Try Again</Button>
            </>
          )}
        </Space>
      </Card>
    </div>
  );
}
