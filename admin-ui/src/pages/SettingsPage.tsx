import {
  Typography,
  Form,
  Input,
  Button,
  Switch,
  Select,
  Card,
  Space,
  Divider,
  message,
  Spin,
  Alert,
  Tabs,
  InputNumber,
} from "antd";
import { SaveOutlined } from "@ant-design/icons";
import { useSettings, useUpdateSettings } from "../hooks/useSettings";
import { useEffect } from "react";

const { Title, Text } = Typography;

// getValueProps for Switch: API sends strings, Switch stores booleans after toggle
const boolProp = (value: unknown) => ({ checked: value === true || value === "true" });

export default function SettingsPage() {
  const { data: settings, isLoading, error } = useSettings();
  const updateSettings = useUpdateSettings();
  const [form] = Form.useForm();
  const pkceEnforced = Form.useWatch("pkce_enforce_s256", form);

  useEffect(() => {
    if (settings) {
      form.setFieldsValue(settings);
    }
  }, [settings, form]);

  const onFinish = async (values: any) => {
    try {
      // Convert booleans to strings if they are switches
      const processed: Record<string, string> = {};
      Object.entries(values).forEach(([k, v]) => {
        if (v === true) processed[k] = "true";
        else if (v === false) processed[k] = "false";
        else if (v !== undefined && v !== null) processed[k] = String(v);
      });

      await updateSettings.mutateAsync(processed);
      message.success("Settings updated successfully");
    } catch {
      message.error("Failed to update settings");
    }
  };

  if (isLoading) return <Spin size="large" />;
  if (error) return <Alert type="error" message="Failed to load settings" />;

  return (
    <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <div>
        <Title level={2}>System Settings</Title>
        <Text type="secondary">
          Configure global policies and defaults for your identity provider.
        </Text>
      </div>

      <Form
        form={form}
        layout="vertical"
        onFinish={onFinish}
        initialValues={settings}
        style={{ maxWidth: 800 }}
      >
        <Tabs
          defaultActiveKey="1"
          items={[
            {
              key: "1",
              label: "Authentication",
              children: (
                <Card variant="borderless">
                  <Form.Item
                    label="Authentication Mode"
                    name="auth_mode"
                    extra="Controls allowed login methods."
                  >
                    <Select>
                      <Select.Option value="password">Password Only</Select.Option>
                      <Select.Option value="password_and_passkey">Password & Passkey</Select.Option>
                      <Select.Option value="passkey_only">Passkey Only</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Allow Self Signup"
                    name="allow_self_signup"
                    valuePropName="checked"
                    getValueProps={boolProp}
                  >
                    <Switch />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>Multi-Factor Authentication</Title>
                  <Form.Item
                    label="Enable MFA"
                    name="mfa_enabled"
                    valuePropName="checked"
                    getValueProps={boolProp}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item label="MFA Method" name="mfa_method">
                    <Select>
                      <Select.Option value="totp">TOTP (Authenticator App)</Select.Option>
                      <Select.Option value="email">Email OTP</Select.Option>
                      <Select.Option value="both">Both (Prefer TOTP)</Select.Option>
                    </Select>
                  </Form.Item>

                  <Divider />

                  <Title level={5}>Session Control</Title>
                  <Form.Item
                    label="SSO Session Idle Timeout"
                    name="sso_session_idle_timeout"
                    extra="Duration of inactivity before SSO session expires (e.g. 30m, 24h). 0 to disable."
                  >
                    <Input placeholder="30m" />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Enabled"
                    name="trust_device_enabled"
                    valuePropName="checked"
                    getValueProps={boolProp}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Expiration"
                    name="trust_device_expiration"
                    extra="How long a device remains trusted (e.g. 720h)."
                  >
                    <Input placeholder="720h" />
                  </Form.Item>
                </Card>
              ),
            },
            {
              key: "2",
              label: "Security & Validation",
              children: (
                <Card variant="borderless">
                  <Title level={5}>User Validation</Title>
                  <Space size="large">
                    <Form.Item label="Min Username" name="validation_min_username_length">
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item label="Max Username" name="validation_max_username_length">
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Space size="large">
                    <Form.Item label="Min Password" name="validation_min_password_length">
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item label="Max Password" name="validation_max_password_length">
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Form.Item
                    label="Username is Email"
                    name="validation_username_is_email"
                    valuePropName="checked"
                    getValueProps={boolProp}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Email Required"
                    name="validation_email_required"
                    valuePropName="checked"
                    getValueProps={boolProp}
                  >
                    <Switch />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>Account Lockout</Title>
                  <Form.Item
                    label="Max Failed Attempts"
                    name="account_lockout_max_attempts"
                    extra="0 to disable lockout"
                  >
                    <InputNumber min={0} />
                  </Form.Item>
                  <Form.Item label="Lockout Duration" name="account_lockout_duration">
                    <Input placeholder="15m" />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>PKCE</Title>
                  <Form.Item
                    label="Enforce S256 Code Challenge"
                    name="pkce_enforce_s256"
                    valuePropName="checked"
                    getValueProps={boolProp}
                  >
                    <Switch />
                  </Form.Item>
                  {(pkceEnforced === false || pkceEnforced === "false") && (
                    <Alert
                      type="warning"
                      showIcon
                      message="Security Warning"
                      description={
                        <>
                          Clients may now use{" "}
                          <code>code_challenge_method=plain</code>, which provides no
                          security benefit — the verifier equals the challenge and is
                          visible in the authorization request. Only disable for
                          backward compatibility with legacy clients that cannot
                          support S256 (RFC 7636).
                        </>
                      }
                      style={{ marginBottom: 16 }}
                    />
                  )}
                </Card>
              ),
            },
            {
              key: "3",
              label: "SMTP & Tokens",
              children: (
                <Card variant="borderless">
                  <Title level={5}>Token Expiration</Title>
                  <Form.Item label="Access Token" name="access_token_expiration">
                    <Input placeholder="15m" />
                  </Form.Item>
                  <Form.Item label="Refresh Token" name="refresh_token_expiration">
                    <Input placeholder="720h" />
                  </Form.Item>
                  <Form.Item label="Auth Code" name="authorization_code_expiration">
                    <Input placeholder="10m" />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>SMTP Configuration</Title>
                  <Form.Item label="SMTP Host" name="smtp_host">
                    <Input placeholder="smtp.example.com" />
                  </Form.Item>
                  <Form.Item label="SMTP Port" name="smtp_port">
                    <Input placeholder="587" />
                  </Form.Item>
                  <Form.Item label="SMTP Username" name="smtp_username">
                    <Input />
                  </Form.Item>
                  <Form.Item label="SMTP Password" name="smtp_password">
                    <Input.Password placeholder="Leave empty to keep current" />
                  </Form.Item>
                  <Form.Item label="SMTP From Address" name="smtp_from">
                    <Input placeholder="noreply@example.com" />
                  </Form.Item>
                </Card>
              ),
            },
            {
              key: "4",
              label: "Branding",
              children: (
                <Card variant="borderless">
                  <Form.Item label="Page Title" name="theme_title">
                    <Input />
                  </Form.Item>
                  <Form.Item label="Logo URL" name="theme_logo_url">
                    <Input placeholder="https://..." />
                  </Form.Item>
                  <Form.Item label="Passkey RP Name" name="passkey_rp_name">
                    <Input />
                  </Form.Item>
                </Card>
              ),
            },
          ]}
        />

        <div style={{ marginTop: 24, textAlign: "right" }}>
          <Button
            type="primary"
            htmlType="submit"
            icon={<SaveOutlined />}
            loading={updateSettings.isPending}
            size="large"
          >
            Save All Settings
          </Button>
        </div>
      </Form>
    </Space>
  );
}
