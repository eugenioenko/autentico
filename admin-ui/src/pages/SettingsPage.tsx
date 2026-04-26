import {
  Typography,
  Form,
  Input,
  Button,
  Checkbox,
  ConfigProvider,
  Select,
  Tooltip,
  Space,
  Divider,
  Spin,
  Alert,
  Tabs,
  InputNumber,
  Table,
  Tag,
  App,
} from "antd";
import {
  SaveOutlined,
  ExclamationCircleOutlined,
  DownloadOutlined,
  UploadOutlined,
  PlusOutlined,
  DeleteOutlined,
} from "@ant-design/icons";
import { useSettings, useUpdateSettings } from "../hooks/useSettings";
import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import apiClient from "../api/client";
import DurationInput from "../components/DurationInput";
import RetentionInput from "../components/RetentionInput";
import { makeTip } from "../lib/tips";

const { Title, Text } = Typography;

const boolProp = (value: unknown) => ({ checked: value === true || value === "true" });

const tabTheme = {
  components: {
    Checkbox: { controlInteractiveSize: 24 },
  },
};

function TabContent({ children }: { children: React.ReactNode }) {
  return (
    <ConfigProvider theme={tabTheme}>
      <div style={{ maxWidth: 800, paddingTop: 24 }}>{children}</div>
    </ConfigProvider>
  );
}

interface PreviewRow {
  key: string;
  current: string;
  incoming: string;
}
interface PreviewResponse {
  rows: PreviewRow[];
  unknown: string[];
}

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
  sso_enabled: "Enable Single Sign-On. When enabled, returning users with an active session are automatically re-authorized without entering credentials.",
  sso_session_idle_timeout: "Duration of inactivity before SSO session expires (e.g. 30m, 24h). 0 for no idle expiration.",
  sso_session_max_age: "Absolute maximum lifetime for SSO sessions, regardless of activity (e.g. 720h for 30 days). 0 for no limit.",
  trust_device_enabled: "Allow users to trust their current device for MFA.",
  trust_device_expiration: "How long a device remains trusted (e.g. 720h).",
  validation_min_username_length: "Minimum length for usernames.",
  validation_max_username_length: "Maximum length for usernames.",
  validation_min_password_length: "Minimum length for passwords.",
  validation_max_password_length: "Maximum length for passwords.",
  account_lockout_max_attempts: "Maximum number of failed login attempts before account lockout. 0 to disable.",
  account_lockout_duration: "Duration of account lockout (e.g. 15m).",
  audit_log_retention: "How long audit events are kept. 0 = disabled, -1 = keep forever, or a duration (e.g. 720h for 30 days).",
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
  footer_links: "Links shown in the footer of login and signup pages (e.g. Terms of Service, Privacy Policy).",
  theme_title: "Custom title for the login and account pages.",
  theme_logo_url: "URL for the custom logo shown on login and account pages.",
  theme_css_inline: "Custom CSS appended to the login and account pages. Served as an external stylesheet, so admin CSS cannot break out into HTML.",
  passkey_rp_name: "Relying Party name shown during passkey creation/usage.",
}, "https://autentico.top/configuration/runtime-settings");

interface FooterLink {
  label: string;
  url: string;
}

function FooterLinksEditor({ value, onChange }: { value?: string; onChange?: (v: string) => void }) {
  const links: FooterLink[] = (() => {
    try { return JSON.parse(value || "[]"); } catch { return []; }
  })();

  const update = (next: FooterLink[]) => onChange?.(JSON.stringify(next));

  const handleChange = (index: number, field: keyof FooterLink, v: string) => {
    const next = [...links];
    next[index] = { ...next[index], [field]: v };
    update(next);
  };

  return (
    <Space direction="vertical" size="small" style={{ width: "100%" }}>
      {links.map((link, i) => (
        <Space key={i} style={{ width: "100%" }}>
          <Input
            style={{ width: 160 }}
            value={link.label}
            onChange={(e) => handleChange(i, "label", e.target.value)}
            placeholder="Label"
          />
          <Input
            style={{ width: 320 }}
            value={link.url}
            onChange={(e) => handleChange(i, "url", e.target.value)}
            placeholder="https://..."
          />
          <Button icon={<DeleteOutlined />} danger onClick={() => update(links.filter((_, j) => j !== i))} />
        </Space>
      ))}
      <Button type="dashed" icon={<PlusOutlined />} onClick={() => update([...links, { label: "", url: "" }])} style={{ width: "100%" }}>
        Add Link
      </Button>
    </Space>
  );
}

export default function SettingsPage() {
  const { message } = App.useApp();
  const { data: settings, isLoading, error } = useSettings();
  const updateSettings = useUpdateSettings();
  const queryClient = useQueryClient();
  const [form] = Form.useForm();
  const pkceEnforced = Form.useWatch("pkce_enforce_s256", form);
  const mfaMethod = Form.useWatch("mfa_method", form);
  const smtpHost = Form.useWatch("smtp_host", form);
  const emailMfaWithoutSmtp = (mfaMethod === "email" || mfaMethod === "both") && !smtpHost;
  const requireEmailVerification = Form.useWatch("require_email_verification", form);
  const emailVerifyWithoutSmtp = (requireEmailVerification === true || requireEmailVerification === "true") && !smtpHost;
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [backupText, setBackupText] = useState("");
  const [previewData, setPreviewData] = useState<PreviewResponse | null>(null);
  const [activeTab, setActiveTab] = useState("1");
  const [exportLoading, setExportLoading] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [applyLoading, setApplyLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleExport = async () => {
    setExportLoading(true);
    try {
      const res = await apiClient.get("/admin/api/settings/export");
      const json = JSON.stringify(res.data.data, null, 2);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "autentico-settings.json";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      message.error("Failed to export settings");
    } finally {
      setExportLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setBackupText((ev.target?.result as string) ?? "");
      setPreviewData(null);
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handlePreview = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(backupText);
    } catch {
      message.error("Invalid JSON — check the pasted content");
      return;
    }
    setPreviewLoading(true);
    try {
      const res = await apiClient.post("/admin/api/settings/import/preview", parsed);
      setPreviewData(res.data.data as PreviewResponse);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      message.error(axiosErr.response?.data?.error_description ?? "Preview failed");
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleApply = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(backupText);
    } catch {
      message.error("Invalid JSON");
      return;
    }
    setApplyLoading(true);
    try {
      await apiClient.post("/admin/api/settings/import/apply", parsed);
      message.success("Settings imported successfully");
      setPreviewData(null);
      setBackupText("");
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      message.error(axiosErr.response?.data?.error_description ?? "Import failed");
    } finally {
      setApplyLoading(false);
    }
  };

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
    <div className="settings-page" style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <style>{`.settings-page input, .settings-page .ant-select, .settings-page .ant-input-password { max-width: 400px; }`}</style>
      <Form
        form={form}
        layout="vertical"
        onFinish={onFinish}
        initialValues={settings}
        style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}
      >
      <div style={{ flex: 1, overflow: "auto", padding: "0 0 16px" }}>
      <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <Title level={2} style={{ marginBottom: 0 }}>System Settings</Title>
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={[
            {
              key: "1",
              label: "Login & Registration",
              children: (
                <TabContent>
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

                  <Form.Item name="allow_self_signup" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Allow Self Signup{' '}
                      <Tooltip title={tip("allow_self_signup")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item name="allow_username_change" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Allow Username Change{' '}
                      <Tooltip title={tip("allow_username_change")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item name="allow_email_change" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Allow Email Change{' '}
                      <Tooltip title={tip("allow_email_change")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item name="allow_self_service_deletion" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Allow Self-Service Deletion{' '}
                      <Tooltip title={tip("allow_self_service_deletion")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>Email Verification</Title>
                  <Form.Item name="require_email_verification" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Require Email Verification{' '}
                      <Tooltip title={tip("require_email_verification")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>
                  {emailVerifyWithoutSmtp && (
                    <Alert
                      type="warning"
                      showIcon
                      message="SMTP not configured"
                      description="Email verification requires a configured SMTP server. Go to the SMTP tab to set it up."
                      style={{ marginBottom: 16 }}
                    />
                  )}
                  <Form.Item
                    label="Verification Link Expiration"
                    name="email_verification_expiration"
                    tooltip={{ title: tip("email_verification_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                </TabContent>
              ),
            },
            {
              key: "2",
              label: "MFA & Trusted Devices",
              children: (
                <TabContent>
                  <Form.Item name="require_mfa" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Require MFA{' '}
                      <Tooltip title={tip("require_mfa")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
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
                      description="Email OTP requires a configured SMTP server. Go to the SMTP tab to set it up, otherwise email MFA will fail at login."
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>Trusted Devices</Title>
                  <Form.Item name="trust_device_enabled" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Trust Device Enabled{' '}
                      <Tooltip title={tip("trust_device_enabled")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Expiration"
                    name="trust_device_expiration"
                    tooltip={{ title: tip("trust_device_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>Passkeys</Title>
                  <Form.Item
                    label="Passkey RP Name"
                    name="passkey_rp_name"
                    tooltip={{ title: tip("passkey_rp_name"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input />
                  </Form.Item>
                </TabContent>
              ),
            },
            {
              key: "3",
              label: "Sessions & Tokens",
              children: (
                <TabContent>
                  <Title level={5} style={{ marginTop: 0 }}>SSO Sessions</Title>
                  <Form.Item name="sso_enabled" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      SSO Enabled{' '}
                      <Tooltip title={tip("sso_enabled")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>
                  <Form.Item
                    label="SSO Session Idle Timeout"
                    name="sso_session_idle_timeout"
                    tooltip={{ title: tip("sso_session_idle_timeout"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                  <Form.Item
                    label="SSO Session Max Age"
                    name="sso_session_max_age"
                    tooltip={{ title: tip("sso_session_max_age"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>Token Expiration</Title>
                  <Form.Item
                    label="Access Token"
                    name="access_token_expiration"
                    tooltip={{ title: tip("access_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                  <Form.Item
                    label="Refresh Token"
                    name="refresh_token_expiration"
                    tooltip={{ title: tip("refresh_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                  <Form.Item
                    label="Auth Code"
                    name="authorization_code_expiration"
                    tooltip={{ title: tip("authorization_code_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                </TabContent>
              ),
            },
            {
              key: "4",
              label: "Security",
              children: (
                <TabContent>
                  <Title level={5} style={{ marginTop: 0 }}>User Validation</Title>
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

                  <Title level={5} style={{ marginTop: 0 }}>Account Lockout</Title>
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
                    <DurationInput />
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>PKCE</Title>
                  <Form.Item name="pkce_enforce_s256" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Enforce S256 Code Challenge{' '}
                      <Tooltip title={tip("pkce_enforce_s256")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
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

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>Audit Log</Title>
                  <Form.Item
                    label="Audit Log Retention"
                    name="audit_log_retention"
                    tooltip={{ title: tip("audit_log_retention"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <RetentionInput />
                  </Form.Item>
                </TabContent>
              ),
            },
            {
              key: "5",
              label: "SMTP",
              children: (
                <TabContent>
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
                </TabContent>
              ),
            },
            {
              key: "6",
              label: "Profile Fields",
              children: (
                <TabContent>
                  <Text type="secondary" style={{ display: "block", marginBottom: 20 }}>
                    Control which profile fields are shown on the signup form and the
                    self-service account portal. <strong>Hidden</strong> fields are never
                    displayed. <strong>Optional</strong> fields are shown but not required.{" "}
                    <strong>Required</strong> fields must be filled before the account is created.
                  </Text>

                  <Form.Item name="signup_show_optional_fields" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      Show Optional Fields on Signup{' '}
                      <Tooltip title={tip("signup_show_optional_fields")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
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
                </TabContent>
              ),
            },
            {
              key: "7",
              label: "Branding",
              children: (
                <TabContent>
                  <Text type="secondary" style={{ display: "block", marginBottom: 20 }}>
                    Customize the appearance of login, signup, and account pages.
                    Set a page title, upload a logo, and use custom CSS to match your
                    brand. Footer links let you add Terms of Service, Privacy Policy, or
                    any other links below the login form. Changes apply to all user-facing
                    pages served by the identity provider.
                  </Text>

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
                    label="Custom CSS"
                    name="theme_css_inline"
                    tooltip={{ title: tip("theme_css_inline"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input.TextArea
                      rows={8}
                      autoSize={{ minRows: 8, maxRows: 24 }}
                      placeholder=":root { --color-primary-bg: #ff7b00; }"
                      style={{ fontFamily: "monospace", fontSize: 13 }}
                    />
                  </Form.Item>
                  <Divider />
                  <Form.Item
                    label="Footer Links"
                    name="footer_links"
                    tooltip={{ title: tip("footer_links"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <FooterLinksEditor />
                  </Form.Item>
                </TabContent>
              ),
            },
            {
              key: "8",
              label: "Backup",
              children: (
                <TabContent>
                  <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <div>
                      <Title level={5} style={{ marginTop: 0, marginBottom: 4 }}>Export</Title>
                      <Text type="secondary" style={{ display: "block", marginBottom: 12 }}>
                        Download all settings as a JSON file.
                      </Text>
                      <Button
                        icon={<DownloadOutlined />}
                        loading={exportLoading}
                        onClick={handleExport}
                      >
                        Download Settings
                      </Button>
                    </div>

                    <Divider />

                    <div>
                      <Title level={5} style={{ marginTop: 0, marginBottom: 4 }}>Import</Title>
                      <Text type="secondary" style={{ display: "block", marginBottom: 12 }}>
                        Paste a settings JSON file below or upload one. Preview changes before applying.
                      </Text>
                      <Space style={{ marginBottom: 8 }}>
                        <input
                          type="file"
                          accept=".json,application/json"
                          ref={fileInputRef}
                          style={{ display: "none" }}
                          onChange={handleFileUpload}
                        />
                        <Button
                          icon={<UploadOutlined />}
                          onClick={() => fileInputRef.current?.click()}
                        >
                          Upload File
                        </Button>
                      </Space>
                      <Input.TextArea
                        value={backupText}
                        onChange={(e) => {
                          setBackupText(e.target.value);
                          setPreviewData(null);
                        }}
                        placeholder='Paste settings JSON here or upload a file…'
                        rows={8}
                        style={{ fontFamily: "monospace", fontSize: 12 }}
                      />
                      <div style={{ marginTop: 12, textAlign: "right" }}>
                        <Space>
                          <Button
                            onClick={handlePreview}
                            loading={previewLoading}
                            disabled={!backupText.trim()}
                          >
                            Preview Import
                          </Button>
                          {previewData && (
                            <Button
                              type="primary"
                              onClick={handleApply}
                              loading={applyLoading}
                            >
                              Apply Import
                            </Button>
                          )}
                        </Space>
                      </div>
                    </div>

                    {previewData && (
                      <>
                        {previewData.unknown.length > 0 && (
                          <Alert
                            type="warning"
                            showIcon
                            message="Unknown keys will be skipped"
                            description={
                              <Space wrap>
                                {previewData.unknown.map((k) => (
                                  <Tag key={k}>{k}</Tag>
                                ))}
                              </Space>
                            }
                          />
                        )}
                        <Table
                          dataSource={previewData.rows}
                          rowKey="key"
                          size="small"
                          pagination={false}
                          rowClassName={(row) =>
                            row.current !== row.incoming ? "ant-table-row-changed" : ""
                          }
                          columns={[
                            {
                              title: "Setting",
                              dataIndex: "key",
                              key: "key",
                              width: "35%",
                              render: (v: string) => <code style={{ fontSize: 12 }}>{v}</code>,
                            },
                            {
                              title: "Current Value",
                              dataIndex: "current",
                              key: "current",
                              width: "32%",
                              render: (v: string) => (
                                <span style={{ color: "var(--ant-color-text-secondary)", fontSize: 12 }}>
                                  {v || <em style={{ opacity: 0.4 }}>empty</em>}
                                </span>
                              ),
                            },
                            {
                              title: "New Value",
                              dataIndex: "incoming",
                              key: "incoming",
                              width: "32%",
                              render: (v: string, row: PreviewRow) => (
                                <span
                                  style={{
                                    fontSize: 12,
                                    fontWeight: row.current !== row.incoming ? 600 : undefined,
                                    color:
                                      row.current !== row.incoming
                                        ? "var(--ant-color-warning-text)"
                                        : undefined,
                                  }}
                                >
                                  {v || <em style={{ opacity: 0.4 }}>empty</em>}
                                </span>
                              ),
                            },
                          ]}
                        />
                      </>
                    )}
                  </Space>
                </TabContent>
              ),
            },
          ]}
        />

    </Space>
    </div>

        {activeTab !== "8" && (
          <div style={{ borderTop: "1px solid var(--ant-color-border)", padding: "16px 0", textAlign: "right" }}>
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
        )}
      </Form>
    </div>
  );
}
