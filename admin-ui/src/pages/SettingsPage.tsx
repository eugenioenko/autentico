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
import { SaveOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
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
                    tooltip={{ title: "Controls allowed login methods.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="password">Password Only</Select.Option>
                      <Select.Option value="password_and_passkey">Password & Passkey</Select.Option>
                      <Select.Option value="passkey_only">Passkey Only</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Email Field Behavior"
                    name="profile_field_email"
                    tooltip={{ title: "Hidden: no email field. Optional: email field shown but not required. Required: email field required. Username is Email: username field acts as email (stored in both columns).", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                      <Select.Option value="is_username">Username is Email</Select.Option>
                    </Select>
                  </Form.Item>


                  <Form.Item
                    label="Allow Self Signup"
                    name="allow_self_signup"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: "Allow users to create their own accounts.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Allow Username Change"
                    name="allow_username_change"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: "Let users change their own username from the account portal.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Allow Email Change"
                    name="allow_email_change"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: "Let users change their own email address from the account portal.", icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: "Require users to provide a second authentication factor.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item label="MFA Method" name="mfa_method" tooltip={{ title: "Preferred second-factor authentication method.", icon: <ExclamationCircleOutlined /> }}>
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
                    tooltip={{ title: "Duration of inactivity before SSO session expires (e.g. 30m, 24h). 0 to disable.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="30m" />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Enabled"
                    name="trust_device_enabled"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: "Allow users to trust their current device for MFA.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Expiration"
                    name="trust_device_expiration"
                    tooltip={{ title: "How long a device remains trusted (e.g. 720h).", icon: <ExclamationCircleOutlined /> }}
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
                    <Form.Item label="Min Username" name="validation_min_username_length" tooltip={{ title: "Minimum length for usernames.", icon: <ExclamationCircleOutlined /> }}>
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item label="Max Username" name="validation_max_username_length" tooltip={{ title: "Maximum length for usernames.", icon: <ExclamationCircleOutlined /> }}>
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Space size="large">
                    <Form.Item label="Min Password" name="validation_min_password_length" tooltip={{ title: "Minimum length for passwords.", icon: <ExclamationCircleOutlined /> }}>
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item label="Max Password" name="validation_max_password_length" tooltip={{ title: "Maximum length for passwords.", icon: <ExclamationCircleOutlined /> }}>
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Divider />

                  <Title level={5}>Account Lockout</Title>
                  <Form.Item
                    label="Max Failed Attempts"
                    name="account_lockout_max_attempts"
                    tooltip={{ title: "Maximum number of failed login attempts before account lockout. 0 to disable.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <InputNumber min={0} />
                  </Form.Item>
                  <Form.Item label="Lockout Duration" name="account_lockout_duration" tooltip={{ title: "Duration of account lockout (e.g. 15m).", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="15m" />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>PKCE</Title>
                  <Form.Item
                    label="Enforce S256 Code Challenge"
                    name="pkce_enforce_s256"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: "Enforce PKCE with S256 code challenge method for all clients.", icon: <ExclamationCircleOutlined /> }}
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
                  <Form.Item label="Access Token" name="access_token_expiration" tooltip={{ title: "Access token validity period (e.g. 15m).", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="15m" />
                  </Form.Item>
                  <Form.Item label="Refresh Token" name="refresh_token_expiration" tooltip={{ title: "Refresh token validity period (e.g. 720h).", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="720h" />
                  </Form.Item>
                  <Form.Item label="Auth Code" name="authorization_code_expiration" tooltip={{ title: "Authorization code validity period (e.g. 10m).", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="10m" />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>SMTP Configuration</Title>
                  <Form.Item label="SMTP Host" name="smtp_host" tooltip={{ title: "Hostname of the SMTP server.", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="smtp.example.com" />
                  </Form.Item>
                  <Form.Item label="SMTP Port" name="smtp_port" tooltip={{ title: "Port for the SMTP server.", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="587" />
                  </Form.Item>
                  <Form.Item label="SMTP Username" name="smtp_username" tooltip={{ title: "Username for SMTP authentication.", icon: <ExclamationCircleOutlined /> }}>
                    <Input />
                  </Form.Item>
                  <Form.Item label="SMTP Password" name="smtp_password" tooltip={{ title: "Password for SMTP authentication. Leave empty to keep current.", icon: <ExclamationCircleOutlined /> }}>
                    <Input.Password placeholder="Leave empty to keep current" />
                  </Form.Item>
                  <Form.Item label="SMTP From Address" name="smtp_from" tooltip={{ title: "Email address to use as the sender for system emails.", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="noreply@example.com" />
                  </Form.Item>
                </Card>
              ),
            },
            {
              key: "4",
              label: "Profile Fields",
              children: (
                <Card variant="borderless">
                  <Text type="secondary" style={{ display: "block", marginBottom: 20 }}>
                    Control which profile fields are shown on the signup form and the
                    self-service account portal. <strong>Hidden</strong> fields are never
                    displayed. <strong>Optional</strong> fields are shown but not required.{" "}
                    <strong>Required</strong> fields must be filled before the account is created.
                  </Text>

                  <Form.Item
                    label="Show Optional Fields on Signup"
                    name="signup_show_optional_fields"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: "When off (default), optional fields are hidden during signup to keep the form minimal. Required fields are always shown.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Divider />

                  <Form.Item
                    label="First Name"
                    name="profile_field_given_name"
                    tooltip={{ title: "Controls the given_name (first name) field.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Last Name"
                    name="profile_field_family_name"
                    tooltip={{ title: "Controls the family_name (last name) field.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Phone Number"
                    name="profile_field_phone"
                    tooltip={{ title: "Controls the phone_number field.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Profile Picture"
                    name="profile_field_picture"
                    tooltip={{ title: "Controls the picture field (URL to avatar image).", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Locale"
                    name="profile_field_locale"
                    tooltip={{ title: "Controls the locale field (e.g. en-US).", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Address"
                    name="profile_field_address"
                    tooltip={{ title: "Controls all address fields (street, city, region, postal code, country) as a group.", icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>
                </Card>
              ),
            },
            {
              key: "5",
              label: "Branding",
              children: (
                <Card variant="borderless">
                  <Form.Item label="Page Title" name="theme_title" tooltip={{ title: "Custom title for the login and account pages.", icon: <ExclamationCircleOutlined /> }}>
                    <Input />
                  </Form.Item>
                  <Form.Item label="Logo URL" name="theme_logo_url" tooltip={{ title: "URL for the custom logo shown on login and account pages.", icon: <ExclamationCircleOutlined /> }}>
                    <Input placeholder="https://..." />
                  </Form.Item>
                  <Form.Item label="Passkey RP Name" name="passkey_rp_name" tooltip={{ title: "Relying Party name shown during passkey creation/usage.", icon: <ExclamationCircleOutlined /> }}>
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
