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
import { useTranslation } from "react-i18next";

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
  theme_brand_color: "Brand color used for action buttons on login pages and transactional emails. Default: #18181b.",
  theme_tagline: "Optional tagline shown below the logo on login pages and in emails.",
  email_footer_text: "Optional text shown in the email footer (e.g. copyright, company address). Supports multiple lines.",
  passkey_rp_name: "Relying Party name shown during passkey creation/usage.",
  passkey_login_mode: "How passkeys are presented on the login page. Username First: user enters username first. Discoverable: button triggers usernameless login. Conditional: browser auto-surfaces passkeys via autofill. Passkey Only: no username field, only passkey login.",
  magic_link_enabled: "Allow users to sign in via a magic link sent to their email, without entering a password. Requires SMTP.",
  magic_link_expiration: "How long a magic link remains valid (e.g. 15m, 30m).",
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
            placeholder="标签"
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
        添加链接
      </Button>
    </Space>
  );
}

export default function SettingsPage() {
  const { message } = App.useApp();
  const { t } = useTranslation();
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
  const magicLinkEnabled = Form.useWatch("magic_link_enabled", form);
  const magicLinkWithoutSmtp = (magicLinkEnabled === true || magicLinkEnabled === "true") && !smtpHost;
  const authMode = Form.useWatch("auth_mode", form);
  const passkeyLoginMode = Form.useWatch("passkey_login_mode", form);
  const profileFieldEmail = Form.useWatch("profile_field_email", form);
  const passkeyModeWithoutPasskeys = passkeyLoginMode && passkeyLoginMode !== "username_first" && authMode === "password";
  const passkeyOnlyWithPasswordFallback = passkeyLoginMode === "passkey_only" && authMode === "password_and_passkey";

  const authModeDescriptions: Record<string, string> = {
    password: "Users log in with username and password only. Passkey options are disabled on the login page.",
    password_and_passkey: "Users can log in with either password or passkey. Both options are shown on the login page.",
    passkey_only: "Users log in with passkeys only. Password and username fields are hidden from the login page.",
  };
  const passkeyLoginModeDescriptions: Record<string, string> = {
    username_first: "User enters their username first, then authenticates with their registered passkey.",
    discoverable: "A \"Sign in with passkey\" button lets users log in without entering a username. The browser shows all passkeys registered for this site.",
    conditional: "The browser automatically surfaces registered passkeys in the username field's autofill dropdown when the login page loads.",
    passkey_only: "Only passkey login is available — no username or password fields are shown. Requires Authentication Mode set to Passkey Only to fully hide the username field.",
  };
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
      message.error("导出设置失败");
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
      message.error("无效的 JSON — 请检查粘贴的内容");
      return;
    }
    setPreviewLoading(true);
    try {
      const res = await apiClient.post("/admin/api/settings/import/preview", parsed);
      setPreviewData(res.data.data as PreviewResponse);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      message.error(axiosErr.response?.data?.error_description ?? "预览失败");
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleApply = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(backupText);
    } catch {
      message.error("无效的 JSON");
      return;
    }
    setApplyLoading(true);
    try {
      await apiClient.post("/admin/api/settings/import/apply", parsed);
      message.success("设置已成功导入");
      setPreviewData(null);
      setBackupText("");
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      message.error(axiosErr.response?.data?.error_description ?? "导入失败");
    } finally {
      setApplyLoading(false);
    }
  };

  const handleTestSmtp = async () => {
    setTestingSmtp(true);
    try {
      await apiClient.post("/admin/api/settings/test-smtp");
      message.success("测试邮件已发送 — 请检查收件箱");
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      const msg = axiosErr.response?.data?.error_description ?? "发送测试邮件失败";
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
      message.success("设置已成功更新");
    } catch {
      message.error("更新设置失败");
    }
  };

  if (isLoading) return <Spin size="large" />;
  if (error) return <Alert type="error" message="加载设置失败" />;

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
      <Title level={2} style={{ marginBottom: 0 }}>{t("settings.systemSettings")}</Title>
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={[
            {
              key: "1",
              label: t("settings.loginAndRegistration"),
              children: (
                <TabContent>
                  <Form.Item
                    label={t("settings.authMode")}
                    name="auth_mode"
                    tooltip={{ title: tip("auth_mode"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="password">{t("settings.passwordOnly")}</Select.Option>
                      <Select.Option value="password_and_passkey">{t("settings.passwordAndPasskey")}</Select.Option>
                      <Select.Option value="passkey_only">{t("settings.passkeyOnly")}</Select.Option>
                    </Select>
                  </Form.Item>
                  {authMode && authModeDescriptions[authMode] && form.isFieldTouched("auth_mode") && (
                    <Alert
                      type="info"
                      showIcon
                      message={authModeDescriptions[authMode]}
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  <Form.Item
                    label={t("settings.emailFieldBehavior")}
                    name="profile_field_email"
                    tooltip={{ title: tip("profile_field_email"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">{t("settings.hidden")}</Select.Option>
                      <Select.Option value="optional">{t("common.optional")}</Select.Option>
                      <Select.Option value="required">{t("common.required")}</Select.Option>
                      <Select.Option value="is_username">{t("settings.usernameIsEmail")}</Select.Option>
                    </Select>
                  </Form.Item>
                  {profileFieldEmail === "is_username" && form.isFieldTouched("profile_field_email") && (
                    <Alert
                      type="warning"
                      showIcon
                      message={t("settings.compatibilityWarning")}
                      description={t("settings.compatibilityWarningDesc")}
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  <Form.Item name="allow_self_signup" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                    {t("settings.allowSelfSignup")}{' '}
                      <Tooltip title={tip("allow_self_signup")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item name="allow_username_change" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                    {t("settings.allowUsernameChange")}{' '}
                      <Tooltip title={tip("allow_username_change")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item name="allow_email_change" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                    {t("settings.allowEmailChange")}{' '}
                      <Tooltip title={tip("allow_email_change")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item name="allow_self_service_deletion" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                    {t("settings.allowSelfServiceDeletion")}{' '}
                      <Tooltip title={tip("allow_self_service_deletion")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.emailVerification")}</Title>
                  <Form.Item name="require_email_verification" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      {t("settings.requireEmailVerification")}{' '}
                      <Tooltip title={tip("require_email_verification")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>
                  {emailVerifyWithoutSmtp && (
                    <Alert
                      type="warning"
                      showIcon
                      message={t("settings.smtpNotConfigured")}
                      description={t("settings.smtpNotConfiguredDesc")}
                      style={{ marginBottom: 16 }}
                    />
                  )}
                  <Form.Item
                    label={t("settings.verificationLinkExpiry")}
                    name="email_verification_expiration"
                    tooltip={{ title: tip("email_verification_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.magicLinkLogin")}</Title>
                  <Form.Item name="magic_link_enabled" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      {t("settings.magicLinkEnabled")}{' '}
                      <Tooltip title={tip("magic_link_enabled")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>
                  {magicLinkWithoutSmtp && (
                    <Alert
                      type="warning"
                      showIcon
                      message="SMTP 未配置"
                      description={t("settings.magicLinkSmtpNotConfiguredDesc")}
                      style={{ marginBottom: 16 }}
                    />
                  )}
                  <Form.Item
                    label={t("settings.magicLinkExpiry")}
                    name="magic_link_expiration"
                    tooltip={{ title: tip("magic_link_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.passkeys")}</Title>
                  <Form.Item
                    label={t("settings.passkeyRpName")}
                    name="passkey_rp_name"
                    tooltip={{ title: tip("passkey_rp_name"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.passkeyLoginMode")}
                    name="passkey_login_mode"
                    tooltip={{ title: tip("passkey_login_mode"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="username_first">{t("settings.usernameFirst")}</Select.Option>
                      <Select.Option value="discoverable">{t("settings.discoverable")}</Select.Option>
                      <Select.Option value="conditional">{t("settings.conditional")}</Select.Option>
                      <Select.Option value="passkey_only">{t("settings.passkeyOnly")}</Select.Option>
                    </Select>
                  </Form.Item>
                  {passkeyLoginMode && passkeyLoginModeDescriptions[passkeyLoginMode] && form.isFieldTouched("passkey_login_mode") && (
                    <Alert
                      type="info"
                      showIcon
                      message={passkeyLoginModeDescriptions[passkeyLoginMode]}
                      style={{ marginBottom: 16 }}
                    />
                  )}
                  {passkeyModeWithoutPasskeys && (
                    <Alert
                      type="warning"
                      showIcon
                      message={t("settings.passkeyLoginDisabled")}
                      description={t("settings.passkeyLoginDisabledDesc")}
                      style={{ marginBottom: 16 }}
                    />
                  )}
                  {passkeyOnlyWithPasswordFallback && (
                    <Alert
                      type="info"
                      showIcon
                      message={t("settings.passwordLoginStillEnabled")}
                      description={t("settings.passwordLoginStillEnabledDesc")}
                      style={{ marginBottom: 16 }}
                    />
                  )}
                </TabContent>
              ),
            },
            {
              key: "2",
              label: t("settings.mfa"),
              children: (
                <TabContent>
                  <Form.Item name="require_mfa" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      {t("settings.requireMfa")}{' '}
                      <Tooltip title={tip("require_mfa")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.mfaMethod")}
                    name="mfa_method"
                    tooltip={{ title: tip("mfa_method"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="totp">{t("settings.totpAuthenticatorApp")}</Select.Option>
                      <Select.Option value="email">{t("settings.emailOtp")}</Select.Option>
                      <Select.Option value="both">{t("settings.bothPreferTotp")}</Select.Option>
                    </Select>
                  </Form.Item>
                  {emailMfaWithoutSmtp && (
                    <Alert
                      type="warning"
                      showIcon
                      message="SMTP 未配置"
                      description={t("settings.emailOtpSmtpNotConfiguredDesc")}
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.trustedDevices")}</Title>
                  <Form.Item name="trust_device_enabled" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      {t("settings.trustedDeviceEnabled")}{' '}
                      <Tooltip title={tip("trust_device_enabled")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.trustedDeviceExpiry")}
                    name="trust_device_expiration"
                    tooltip={{ title: tip("trust_device_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>

                </TabContent>
              ),
            },
            {
              key: "3",
              label: t("settings.sessionsAndTokens"),
              children: (
                <TabContent>
                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.ssoSession")}</Title>
                  <Form.Item name="sso_enabled" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      {t("settings.ssoEnabled")}{' '}
                      <Tooltip title={tip("sso_enabled")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>
                  <Form.Item
                    label={t("settings.ssoSessionIdleTimeout")}
                    name="sso_session_idle_timeout"
                    tooltip={{ title: tip("sso_session_idle_timeout"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.ssoSessionMaxAge")}
                    name="sso_session_max_age"
                    tooltip={{ title: tip("sso_session_max_age"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.tokenExpiry")}</Title>
                  <Form.Item
                    label={t("settings.accessToken")}
                    name="access_token_expiration"
                    tooltip={{ title: tip("access_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.refreshToken")}
                    name="refresh_token_expiration"
                    tooltip={{ title: tip("refresh_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.authorizationCode")}
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
              label: t("settings.securitySettings"),
              children: (
                <TabContent>
                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.userValidation")}</Title>
                  <Space size="large">
                    <Form.Item
                      label={t("settings.minUsername")}
                      name="validation_min_username_length"
                      tooltip={{ title: tip("validation_min_username_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item
                      label={t("settings.maxUsername")}
                      name="validation_max_username_length"
                      tooltip={{ title: tip("validation_max_username_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Space size="large">
                    <Form.Item
                      label={t("settings.minPassword")}
                      name="validation_min_password_length"
                      tooltip={{ title: tip("validation_min_password_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                    <Form.Item
                      label={t("settings.maxPassword")}
                      name="validation_max_password_length"
                      tooltip={{ title: tip("validation_max_password_length"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <InputNumber min={1} />
                    </Form.Item>
                  </Space>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.accountLockout")}</Title>
                  <Form.Item
                    label={t("settings.maxFailedAttempts")}
                    name="account_lockout_max_attempts"
                    tooltip={{ title: tip("account_lockout_max_attempts"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <InputNumber min={0} />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.lockoutDuration")}
                    name="account_lockout_duration"
                    tooltip={{ title: tip("account_lockout_duration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <DurationInput />
                  </Form.Item>

                  <Divider />

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.pkce")}</Title>
                  <Form.Item name="pkce_enforce_s256" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      {t("settings.enforceS256")}{' '}
                      <Tooltip title={tip("pkce_enforce_s256")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>
                  {(pkceEnforced === false || pkceEnforced === "false") && (
                    <Alert
                      type="warning"
                      showIcon
                      message={t("settings.securityWarning")}
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

                  <Title level={5} style={{ marginTop: 0 }}>{t("settings.auditLogRetention")}</Title>
                  <Form.Item
                    label={t("settings.auditLogRetentionLabel")}
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
              label: t("settings.smtp"),
              children: (
                <TabContent>
                  <Form.Item
                    label={t("settings.smtpHost")}
                    name="smtp_host"
                    tooltip={{ title: tip("smtp_host"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="smtp.example.com" />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.smtpPort")}
                    name="smtp_port"
                    tooltip={{ title: tip("smtp_port"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="587" />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.smtpUsername")}
                    name="smtp_username"
                    tooltip={{ title: tip("smtp_username"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input autoComplete="off" />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.smtpPassword")}
                    name="smtp_password"
                    tooltip={{ title: tip("smtp_password"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input.Password placeholder={t("settings.leaveEmptyKeepCurrent")} autoComplete="new-password" />
                  </Form.Item>
                  <Form.Item
                    label={t("settings.smtpFrom")}
                    name="smtp_from"
                    tooltip={{ title: tip("smtp_from"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="noreply@example.com" />
                  </Form.Item>
                  <Form.Item label=" " colon={false}>
                    <Button onClick={handleTestSmtp} loading={testingSmtp} disabled={!smtpHost}>
                      {t("settings.sendTestEmail")}
                    </Button>
                  </Form.Item>
                </TabContent>
              ),
            },
            {
              key: "6",
              label: t("settings.profileFields"),
              children: (
                <TabContent>
                  <Text type="secondary" style={{ display: "block", marginBottom: 20 }}>
                    控制哪些资料字段显示在注册表单和自助服务账户门户中。
                    <strong>隐藏</strong> 的字段不显示。
                    <strong>可选</strong> 的字段显示但不强制要求。{" "}
                    <strong>必填</strong> 的字段必须在创建账户前填写。
                  </Text>

                  <Form.Item name="signup_show_optional_fields" valuePropName="checked" getValueProps={boolProp}>
                    <Checkbox>
                      注册时显示可选字段{' '}
                      <Tooltip title={tip("signup_show_optional_fields")}><ExclamationCircleOutlined /></Tooltip>
                    </Checkbox>
                  </Form.Item>

                  <Divider />

                  <Form.Item
                    label="名字"
                    name="profile_field_given_name"
                    tooltip={{ title: tip("profile_field_given_name"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.familyName")}
                    name="profile_field_family_name"
                    tooltip={{ title: tip("profile_field_family_name"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.middleName")}
                    name="profile_field_middle_name"
                    tooltip={{ title: tip("profile_field_middle_name"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.nickname")}
                    name="profile_field_nickname"
                    tooltip={{ title: tip("profile_field_nickname"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.phoneNumber")}
                    name="profile_field_phone"
                    tooltip={{ title: tip("profile_field_phone"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.picture")}
                    name="profile_field_picture"
                    tooltip={{ title: tip("profile_field_picture"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.website")}
                    name="profile_field_website"
                    tooltip={{ title: tip("profile_field_website"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.profileUrl")}
                    name="profile_field_profile"
                    tooltip={{ title: tip("profile_field_profile"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.gender")}
                    name="profile_field_gender"
                    tooltip={{ title: tip("profile_field_gender"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.birthdate")}
                    name="profile_field_birthdate"
                    tooltip={{ title: tip("profile_field_birthdate"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.locale")}
                    name="profile_field_locale"
                    tooltip={{ title: tip("profile_field_locale"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    label={t("settings.address")}
                    name="profile_field_address"
                    tooltip={{ title: tip("profile_field_address"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select>
                      <Select.Option value="hidden">隐藏</Select.Option>
                      <Select.Option value="optional">可选</Select.Option>
                      <Select.Option value="required">必填</Select.Option>
                    </Select>
                  </Form.Item>
                </TabContent>
              ),
            },
            {
              key: "7",
              label: t("settings.branding"),
              children: (
                <TabContent>
                  <Text type="secondary" style={{ display: "block", marginBottom: 20 }}>
                    自定义登录、注册、账户页面和事务邮件的外观。设置页面标题、Logo、品牌颜色和标语。
                    使用自定义 CSS 进一步匹配您的品牌。页脚链接显示在登录表单下方和邮件中。
                    更改将影响由此身份提供商服务的所有面向用户的页面和邮件。
                  </Text>

                  <Form.Item
                    label="页面标题"
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
                    label="自定义 CSS"
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
                  <Form.Item
                    label="品牌颜色"
                    name="theme_brand_color"
                    tooltip={{ title: tip("theme_brand_color"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="#18181b" />
                  </Form.Item>
                  <Form.Item
                    label="标语"
                    name="theme_tagline"
                    tooltip={{ title: tip("theme_tagline"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder="Simple. Safe. Self-hosted." />
                  </Form.Item>
                  <Form.Item
                    label="邮件页脚文本"
                    name="email_footer_text"
                    tooltip={{ title: tip("email_footer_text"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input.TextArea
                      rows={3}
                      autoSize={{ minRows: 2, maxRows: 6 }}
                      placeholder={"Copyright 2026 Acme Corp.\n123 Main Street, Springfield"}
                    />
                  </Form.Item>
                  <Divider />
                  <Form.Item
                    label="页脚链接"
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
              label: t("settings.backup"),
              children: (
                <TabContent>
                  <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <div>
                      <Title level={5} style={{ marginTop: 0, marginBottom: 4 }}>导出</Title>
                      <Text type="secondary" style={{ display: "block", marginBottom: 12 }}>
                        将所有设置下载为 JSON 文件。
                      </Text>
                      <Button
                        icon={<DownloadOutlined />}
                        loading={exportLoading}
                        onClick={handleExport}
                      >
                        下载设置
                      </Button>
                    </div>

                    <Divider />

                    <div>
                      <Title level={5} style={{ marginTop: 0, marginBottom: 4 }}>导入</Title>
                      <Text type="secondary" style={{ display: "block", marginBottom: 12 }}>
                        粘贴或上传设置 JSON 文件。应用前预览更改。
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
                          上传文件
                        </Button>
                      </Space>
                      <Input.TextArea
                        value={backupText}
                        onChange={(e) => {
                          setBackupText(e.target.value);
                          setPreviewData(null);
                        }}
                        placeholder="在此粘贴设置 JSON 或上传文件…"
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
                            预览导入
                          </Button>
                          {previewData && (
                            <Button
                              type="primary"
                              onClick={handleApply}
                              loading={applyLoading}
                            >
                              应用导入
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
                            message="未知键将被跳过"
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
                              title: "设置",
                              dataIndex: "key",
                              key: "key",
                              width: "35%",
                              render: (v: string) => <code style={{ fontSize: 12 }}>{v}</code>,
                            },
                            {
                              title: "当前值",
                              dataIndex: "current",
                              key: "current",
                              width: "32%",
                              render: (v: string) => (
                                <span style={{ color: "var(--ant-color-text-secondary)", fontSize: 12 }}>
                                  {v || <em style={{ opacity: 0.4 }}>空</em>}
                                </span>
                              ),
                            },
                            {
                              title: "新值",
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
                                  {v || <em style={{ opacity: 0.4 }}>空</em>}
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
              保存所有设置
            </Button>
          </div>
        )}
      </Form>
    </div>
  );
}
