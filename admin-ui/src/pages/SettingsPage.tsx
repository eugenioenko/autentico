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
import { useEffect, useState } from "react";
import apiClient from "../api/client";
import { makeTip } from "../lib/tips";

const { Title, Text } = Typography;

// getValueProps for Switch: API sends strings, Switch stores booleans after toggle
const boolProp = (value: unknown) => ({ checked: value === true || value === "true" });

const tip = makeTip({
  auth_mode: "Controls allowed login methods.",
  profile_field_email: "Hidden: no email field. Optional: shown but not required. Required: field is mandatory. Username is Email: username acts as email (stored in both columns).",
  allow_self_signup: "Allow users to create their own accounts.",
  allow_username_change: "Let users change their own username from the account portal.",
  allow_email_change: "Let users change their own email address from the account portal.",
  allow_self_service_deletion: "When enabled, users can delete their own account immediately without admin approval.",
  require_mfa: "Force all users to complete a second authentication factor at login. Users can also enroll in TOTP voluntarily without this being enabled.",
  mfa_method: "Preferred second-factor authentication method.",
  require_email_verification: "Require users to verify their email address before they can log in. Admins are exempt. Requires SMTP to be configured.",
  email_verification_expiration: "How long a verification link remains valid (e.g. 24h, 48h).",
  sso_session_idle_timeout: "Duration of inactivity before SSO session expires (e.g. 30m, 24h). 0 to disable.",
  trust_device_enabled: "Allow users to trust their current device for MFA.",
  trust_device_expiration: "How long a device remains trusted (e.g. 720h).",
  validation_min_username_length: "Minimum length for usernames.",
  validation_max_username_length: "Maximum length for usernames.",
  validation_min_password_length: "Minimum length for passwords.",
  validation_max_password_length: "Maximum length for passwords.",
  account_lockout_max_attempts: "Maximum number of failed login attempts before account lockout. 0 to disable.",
  account_lockout_duration: "Duration of account lockout (e.g. 15m).",
  pkce_enforce_s256: "Enforce PKCE with S256 code challenge method for all clients.",
  access_token_expiration: "Access token validity period (e.g. 15m).",
  refresh_token_expiration: "Refresh token validity period (e.g. 720h).",
  authorization_code_expiration: "Authorization code validity period (e.g. 10m).",
  smtp_host: "Hostname of the SMTP server.",
  smtp_port: "Port for the SMTP server.",
  smtp_username: "Username for SMTP authentication.",
  smtp_password: "Password for SMTP authentication. Leave empty to keep current.",
  smtp_from: "Email address to use as the sender for system emails.",
  signup_show_optional_fields: "When off (default), optional fields are hidden during signup to keep the form minimal. Required fields are always shown.",
  profile_field_given_name: "Controls the given_name (first name) field.",
  profile_field_family_name: "Controls the family_name (last name) field.",
  profile_field_middle_name: "Controls the middle_name field.",
  profile_field_nickname: "Controls the nickname field.",
  profile_field_phone: "Controls the phone_number field.",
  profile_field_picture: "Controls the picture field (URL to avatar image).",
  profile_field_website: "Controls the website field (URL to the user's personal site).",
  profile_field_gender: "Controls the gender field.",
  profile_field_birthdate: "Controls the birthdate field (ISO 8601 date).",
  profile_field_profile: "Controls the profile field (URL to the user's profile page).",
  profile_field_locale: "Controls the locale field (e.g. en-US).",
  profile_field_address: "Controls all address fields (street, city, region, postal code, country) as a group.",
  theme_title: "Custom title for the login and account pages.",
  theme_logo_url: "URL for the custom logo shown on login and account pages.",
  passkey_rp_name: "Relying Party name shown during passkey creation/usage.",
}, "https://autentico.top/configuration/runtime-settings");

export default function SettingsPage() {
  const { data: settings, isLoading, error } = useSettings();
  const updateSettings = useUpdateSettings();
  const [form] = Form.useForm();
  const pkceEnforced = Form.useWatch("pkce_enforce_s256", form);
  const mfaMethod = Form.useWatch("mfa_method", form);
  const smtpHost = Form.useWatch("smtp_host", form);
  const emailMfaWithoutSmtp = (mfaMethod === "email" || mfaMethod === "both") && !smtpHost;
  const [testingSmtp, setTestingSmtp] = useState(false);

  const handleTestSmtp = async () => {
    setTestingSmtp(true);
    try {
      await apiClient.post("/admin/api/settings/test-smtp");
      message.success("Test email sent — check your inbox");
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      const msg = axiosErr.response?.data?.error_description ?? "Failed to send test email";
      message.error(msg);
    } finally {
      setTestingSmtp(false);
    }
  };

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
                    tooltip={{ title: tip("auth_mode"), icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: tip("profile_field_email"), icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: tip("allow_self_signup"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Allow Username Change"
                    name="allow_username_change"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: tip("allow_username_change"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Allow Email Change"
                    name="allow_email_change"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: tip("allow_email_change"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Allow Self-Service Deletion"
                    name="allow_self_service_deletion"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: tip("allow_self_service_deletion"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>Multi-Factor Authentication</Title>
                  <Form.Item
                    label="Require MFA"
                    name="require_mfa"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: tip("require_mfa"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="MFA Method"
                    name="mfa_method"
                    tooltip={{ title: tip("mfa_method"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="totp">TOTP (Authenticator App)</Select.Option>
                      <Select.Option value="email">Email OTP</Select.Option>
                      <Select.Option value="both">Both (Prefer TOTP)</Select.Option>
                    </Select>
                  </Form.Item>
                  {emailMfaWithoutSmtp && (
                    <Alert
                      type="warning"
                      showIcon
                      message="SMTP not configured"
                      description="Email OTP requires a configured SMTP server. Go to the SMTP & Tokens tab to set it up, otherwise email MFA will fail at login."
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  <Divider />

                  <Title level={5}>Email Verification</Title>
                  <Form.Item
                    label="Require Email Verification"
                    name="require_email_verification"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: tip("require_email_verification"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>
                  <Form.Item
                    label="Verification Link Expiration"
                    name="email_verification_expiration"
                    tooltip={{ title: tip("email_verification_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="24h" />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>Session Control</Title>
                  <Form.Item
                    label="SSO Session Idle Timeout"
                    name="sso_session_idle_timeout"
                    tooltip={{ title: tip("sso_session_idle_timeout"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="30m" />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Enabled"
                    name="trust_device_enabled"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: tip("trust_device_enabled"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Expiration"
                    name="trust_device_expiration"
                    tooltip={{ title: tip("trust_device_expiration"), icon: <ExclamationCircleOutlined /> }}
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
                    <Form.Item
                      label="Min Username"
                      name="validation_min_username_length"
                      tooltip={{ title: tip("validation_min_username_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item
                      label="Max Username"
                      name="validation_max_username_length"
                      tooltip={{ title: tip("validation_max_username_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Space size="large">
                    <Form.Item
                      label="Min Password"
                      name="validation_min_password_length"
                      tooltip={{ title: tip("validation_min_password_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item
                      label="Max Password"
                      name="validation_max_password_length"
                      tooltip={{ title: tip("validation_max_password_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Divider />

                  <Title level={5}>Account Lockout</Title>
                  <Form.Item
                    label="Max Failed Attempts"
                    name="account_lockout_max_attempts"
                    tooltip={{ title: tip("account_lockout_max_attempts"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <InputNumber min={0} />
                  </Form.Item>
                  <Form.Item
                    label="Lockout Duration"
                    name="account_lockout_duration"
                    tooltip={{ title: tip("account_lockout_duration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="15m" />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>PKCE</Title>
                  <Form.Item
                    label="Enforce S256 Code Challenge"
                    name="pkce_enforce_s256"
                    valuePropName="checked"
                    getValueProps={boolProp}
                    tooltip={{ title: tip("pkce_enforce_s256"), icon: <ExclamationCircleOutlined /> }}
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
                  <Form.Item
                    label="Access Token"
                    name="access_token_expiration"
                    tooltip={{ title: tip("access_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="15m" />
                  </Form.Item>
                  <Form.Item
                    label="Refresh Token"
                    name="refresh_token_expiration"
                    tooltip={{ title: tip("refresh_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="720h" />
                  </Form.Item>
                  <Form.Item
                    label="Auth Code"
                    name="authorization_code_expiration"
                    tooltip={{ title: tip("authorization_code_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="10m" />
                  </Form.Item>

                  <Divider />

                  <Title level={5}>SMTP Configuration</Title>
                  <Form.Item
                    label="SMTP Host"
                    name="smtp_host"
                    tooltip={{ title: tip("smtp_host"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="smtp.example.com" />
                  </Form.Item>
                  <Form.Item
                    label="SMTP Port"
                    name="smtp_port"
                    tooltip={{ title: tip("smtp_port"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="587" />
                  </Form.Item>
                  <Form.Item
                    label="SMTP Username"
                    name="smtp_username"
                    tooltip={{ title: tip("smtp_username"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input />
                  </Form.Item>
                  <Form.Item
                    label="SMTP Password"
                    name="smtp_password"
                    tooltip={{ title: tip("smtp_password"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input.Password placeholder="Leave empty to keep current" />
                  </Form.Item>
                  <Form.Item
                    label="SMTP From Address"
                    name="smtp_from"
                    tooltip={{ title: tip("smtp_from"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="noreply@example.com" />
                  </Form.Item>
                  <Form.Item label=" " colon={false}>
                    <Button onClick={handleTestSmtp} loading={testingSmtp} disabled={!smtpHost}>
                      Send Test Email
                    </Button>
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
                    tooltip={{ title: tip("signup_show_optional_fields"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Divider />

                  <Form.Item
                    label="First Name"
                    name="profile_field_given_name"
                    tooltip={{ title: tip("profile_field_given_name"), icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: tip("profile_field_family_name"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Middle Name"
                    name="profile_field_middle_name"
                    tooltip={{ title: tip("profile_field_middle_name"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Nickname"
                    name="profile_field_nickname"
                    tooltip={{ title: tip("profile_field_nickname"), icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: tip("profile_field_phone"), icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: tip("profile_field_picture"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Website"
                    name="profile_field_website"
                    tooltip={{ title: tip("profile_field_website"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Profile Page URL"
                    name="profile_field_profile"
                    tooltip={{ title: tip("profile_field_profile"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Gender"
                    name="profile_field_gender"
                    tooltip={{ title: tip("profile_field_gender"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">Hidden</Select.Option>
                      <Select.Option value="optional">Optional</Select.Option>
                      <Select.Option value="required">Required</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label="Birthdate"
                    name="profile_field_birthdate"
                    tooltip={{ title: tip("profile_field_birthdate"), icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: tip("profile_field_locale"), icon: <ExclamationCircleOutlined /> }}
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
                    tooltip={{ title: tip("profile_field_address"), icon: <ExclamationCircleOutlined /> }}
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
                  <Form.Item
                    label="Page Title"
                    name="theme_title"
                    tooltip={{ title: tip("theme_title"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input />
                  </Form.Item>
                  <Form.Item
                    label="Logo URL"
                    name="theme_logo_url"
                    tooltip={{ title: tip("theme_logo_url"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="https://..." />
                  </Form.Item>
                  <Form.Item
                    label="Passkey RP Name"
                    name="passkey_rp_name"
                    tooltip={{ title: tip("passkey_rp_name"), icon: <ExclamationCircleOutlined /> }}
                  >
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
