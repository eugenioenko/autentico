import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Divider,
  Heading,
  IconButton,
  Inline,
  Input,
  NumberInput,
  Select,
  Spinner,
  Stack,
  Tabs,
  Text,
  Textarea,
  toast,
} from "@yarcl/react";
import { IconDeviceFloppy, IconDownload, IconPlus, IconTrash, IconUpload } from "@tabler/icons-react";
import { Controller, FormProvider, useForm, useFormContext, useWatch, type FieldErrors, type RegisterOptions } from "react-hook-form";
import { useSettings, useUpdateSettings } from "../hooks/useSettings";
import { useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import apiClient from "../api/client";
import DurationInput from "../components/DurationInput";
import RetentionInput from "../components/RetentionInput";
import { FormField, InfoTip } from "../components/FormField";
import FieldGroup from "../components/FieldGroup";
import PasswordInput from "../components/PasswordInput";
import { DataTable, dataColumns } from "../components/DataTable";
import { makeTip } from "../lib/tips";
import { isSettingOn } from "../lib/settings";
import "./SettingsPage.css";

type SettingValue = string | number | boolean | null | undefined;
type SettingsValues = Record<string, SettingValue>;

const isOn = (value: SettingValue) => isSettingOn(value);
const asText = (value: SettingValue) => (value == null ? "" : String(value));

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
  merge_group_claims: "When enabled, inherited group claims are emitted under their local names instead of group.claim, and values from all of a user's groups are combined into a JSON array (always an array, even with one value). Individual claims are unchanged. Reserved names such as role are never emitted.",
  federation_copy_name_claims: "When enabled, copy given_name and family_name from the identity provider's ID token when federation creates a new user. Existing users are not updated. This setting also applies when those fields are hidden from profile forms.",
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
  logout_success_url: "Where the button on the signed-out page links when the logout request did not identify a client with an Application URL. A path like /welcome or an https URL. Leave empty to link to the account page.",
  logout_success_label: "Button text on the signed-out page for the link above. Defaults to \"Continue\" when a URL is set, otherwise \"Go to your profile\".",
  theme_title: "Custom title for the login and account pages.",
  theme_logo_url: "URL for the custom logo shown on login and account pages. Accepts an https URL, a path on this server (/...), or a data:image URI.",
  theme_css_inline: "Custom CSS appended to the login and account pages. Served as an external stylesheet, so admin CSS cannot break out into HTML.",
  theme_brand_color: "Brand color used for action buttons on login pages and transactional emails. Default: #18181b.",
  theme_tagline: "Optional tagline shown below the logo on login pages and in emails.",
  email_footer_text: "Optional text shown in the email footer (e.g. copyright, company address). Supports multiple lines.",
  passkey_rp_name: "Relying Party name shown during passkey creation/usage.",
  passkey_login_mode: "How passkeys are presented on the login page. Username First: user enters username first. Discoverable: button triggers usernameless login. Conditional: browser auto-surfaces passkeys via autofill. Passkey Only: no username field, only passkey login.",
  magic_link_enabled: "Allow users to sign in via a magic link sent to their email, without entering a password. Requires SMTP.",
  magic_link_expiration: "How long a magic link remains valid (e.g. 15m, 30m).",
}, "https://getautentico.dev/configuration/runtime-settings");

const AUTH_MODE_OPTIONS = [
  { value: "password", label: "Password Only" },
  { value: "password_and_passkey", label: "Password & Passkey" },
  { value: "passkey_only", label: "Passkey Only" },
];

const EMAIL_FIELD_OPTIONS = [
  { value: "hidden", label: "Hidden" },
  { value: "optional", label: "Optional" },
  { value: "required", label: "Required" },
  { value: "is_username", label: "Username is Email" },
];

const PASSKEY_LOGIN_MODE_OPTIONS = [
  { value: "username_first", label: "Username First" },
  { value: "discoverable", label: "Discoverable" },
  { value: "conditional", label: "Conditional (Autofill)" },
  { value: "passkey_only", label: "Passkey Only" },
];

const MFA_METHOD_OPTIONS = [
  { value: "totp", label: "TOTP (Authenticator App)" },
  { value: "email", label: "Email OTP" },
  { value: "both", label: "Both (Prefer TOTP)" },
];

const VISIBILITY_OPTIONS = [
  { value: "hidden", label: "Hidden" },
  { value: "optional", label: "Optional" },
  { value: "required", label: "Required" },
];

const PROFILE_FIELDS: [name: string, label: string][] = [
  ["profile_field_given_name", "First Name"],
  ["profile_field_family_name", "Last Name"],
  ["profile_field_middle_name", "Middle Name"],
  ["profile_field_nickname", "Nickname"],
  ["profile_field_phone", "Phone Number"],
  ["profile_field_picture", "Profile Picture"],
  ["profile_field_website", "Website"],
  ["profile_field_profile", "Profile Page URL"],
  ["profile_field_gender", "Gender"],
  ["profile_field_birthdate", "Birthdate"],
  ["profile_field_locale", "Locale"],
  ["profile_field_address", "Address"],
];

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

function validateLogoutUrl(value: SettingValue) {
  const url = asText(value);
  const message = "Use a path starting with / or an https URL";
  if (!url) return true;
  if (url.startsWith("/") && !url.startsWith("//")) return true;
  try {
    const u = new URL(url);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) return true;
  } catch {
    return message;
  }
  return message;
}

type Rules = Omit<RegisterOptions<SettingsValues, string>, "valueAsNumber" | "valueAsDate" | "setValueAs" | "disabled">;

function TextSetting({
  name,
  label,
  placeholder,
  autoComplete,
  password,
  rules,
}: {
  name: string;
  label: string;
  placeholder?: string;
  autoComplete?: string;
  password?: boolean;
  rules?: Rules;
}) {
  const { control } = useFormContext<SettingsValues>();
  return (
    <FormField control={control} name={name} label={label} tooltip={tip(name)} rules={rules}>
      {(field) => {
        const props = {
          className: "settings-control",
          name: field.name,
          ref: field.ref,
          value: asText(field.value),
          onChange: (e: ChangeEvent<HTMLInputElement>) => field.onChange(e.target.value),
          onBlur: field.onBlur,
          placeholder,
          autoComplete,
        };
        return password ? <PasswordInput {...props} /> : <Input {...props} />;
      }}
    </FormField>
  );
}

function TextareaSetting({ name, label, placeholder, rows, code }: { name: string; label: string; placeholder?: string; rows: number; code?: boolean }) {
  const { control } = useFormContext<SettingsValues>();
  return (
    <FormField control={control} name={name} label={label} tooltip={tip(name)}>
      {(field) => (
        <Textarea
          className={code ? "settings-code" : undefined}
          name={field.name}
          ref={field.ref}
          value={asText(field.value)}
          onChange={(e) => field.onChange(e.target.value)}
          onBlur={field.onBlur}
          rows={rows}
          placeholder={placeholder}
        />
      )}
    </FormField>
  );
}

function SelectSetting({ name, label, options }: { name: string; label: string; options: { value: string; label: string }[] }) {
  const { control } = useFormContext<SettingsValues>();
  return (
    <FormField control={control} name={name} label={label} tooltip={tip(name)}>
      {(field) => (
        <Select
          className="settings-control"
          options={options}
          value={field.value == null ? null : String(field.value)}
          onValueChange={field.onChange}
          onBlur={field.onBlur}
        />
      )}
    </FormField>
  );
}

function NumberSetting({ name, label, min }: { name: string; label: string; min: number }) {
  const { control } = useFormContext<SettingsValues>();
  return (
    <FormField control={control} name={name} label={label} tooltip={tip(name)}>
      {(field) => {
        const num = field.value == null || field.value === "" ? null : Number(field.value);
        return (
          <NumberInput
            className="settings-number"
            name={field.name}
            ref={field.ref}
            min={min}
            value={num === null || Number.isNaN(num) ? null : num}
            onValueChange={field.onChange}
            onBlur={field.onBlur}
          />
        );
      }}
    </FormField>
  );
}

function DurationSetting({ name, label }: { name: string; label: string }) {
  const { control } = useFormContext<SettingsValues>();
  return (
    <FormField control={control} name={name} label={label} tooltip={tip(name)}>
      {(field) => <DurationInput value={asText(field.value)} onChange={field.onChange} onBlur={field.onBlur} />}
    </FormField>
  );
}

function CheckSetting({ name, label }: { name: string; label: string }) {
  const { control } = useFormContext<SettingsValues>();
  return (
    <Controller
      control={control}
      name={name}
      render={({ field }) => (
        <Inline gap="xs" align="center">
          <Checkbox
            name={field.name}
            ref={field.ref}
            checked={isOn(field.value)}
            onChange={(e) => field.onChange(e.target.checked)}
            onBlur={field.onBlur}
          >
            {label}
          </Checkbox>
          <InfoTip content={tip(name)} />
        </Inline>
      )}
    />
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Stack gap="md">
      <Heading level={3} textStyle="subheading">
        {title}
      </Heading>
      {children}
    </Stack>
  );
}

interface FooterLink {
  label: string;
  url: string;
}

function FooterLinksEditor({ value, onChange }: { value?: string; onChange?: (v: string) => void }) {
  const links: FooterLink[] = (() => {
    try {
      return JSON.parse(value || "[]");
    } catch {
      return [];
    }
  })();

  const update = (next: FooterLink[]) => onChange?.(JSON.stringify(next));

  const handleChange = (index: number, field: keyof FooterLink, v: string) => {
    const next = [...links];
    next[index] = { ...next[index], [field]: v };
    update(next);
  };

  return (
    <Stack gap="sm">
      {links.map((link, i) => (
        <Inline key={i} gap="sm" wrap={false}>
          <Input
            className="settings-link-label"
            aria-label={`Link ${i + 1} label`}
            value={link.label}
            onChange={(e) => handleChange(i, "label", e.target.value)}
            placeholder="Label"
          />
          <Input
            className="settings-link-url"
            aria-label={`Link ${i + 1} URL`}
            value={link.url}
            onChange={(e) => handleChange(i, "url", e.target.value)}
            placeholder="https://..."
          />
          <IconButton
            variant="outline"
            color="danger"
            aria-label={`Remove link ${i + 1}`}
            onClick={() => update(links.filter((_, j) => j !== i))}
          >
            <IconTrash />
          </IconButton>
        </Inline>
      ))}
      <Button variant="outline" color="neutral" startIcon={<IconPlus />} onClick={() => update([...links, { label: "", url: "" }])}>
        Add Link
      </Button>
    </Stack>
  );
}

function EmptyValue({ value }: { value: string }) {
  return value ? (
    <>{value}</>
  ) : (
    <Text as="em" muted>
      empty
    </Text>
  );
}

export default function SettingsPage() {
  const { data: settings, isLoading, error } = useSettings();
  const updateSettings = useUpdateSettings();
  const queryClient = useQueryClient();
  const form = useForm<SettingsValues>({ shouldUnregister: true });
  const {
    control,
    reset,
    handleSubmit,
    formState: { dirtyFields },
  } = form;
  const [pkceEnforced, mfaMethod, smtpHost, requireEmailVerification, magicLinkEnabled, authMode, passkeyLoginMode, profileFieldEmail] =
    useWatch({
      control,
      name: [
        "pkce_enforce_s256",
        "mfa_method",
        "smtp_host",
        "require_email_verification",
        "magic_link_enabled",
        "auth_mode",
        "passkey_login_mode",
        "profile_field_email",
      ],
    });
  const emailMfaWithoutSmtp = (mfaMethod === "email" || mfaMethod === "both") && !smtpHost;
  const emailVerifyWithoutSmtp = isOn(requireEmailVerification) && !smtpHost;
  const magicLinkWithoutSmtp = isOn(magicLinkEnabled) && !smtpHost;
  const authModeKey = asText(authMode);
  const passkeyLoginModeKey = asText(passkeyLoginMode);
  const passkeyModeWithoutPasskeys = passkeyLoginModeKey && passkeyLoginModeKey !== "username_first" && authModeKey === "password";
  const passkeyOnlyWithPasswordFallback = passkeyLoginModeKey === "passkey_only" && authModeKey === "password_and_passkey";

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
      toast({ title: "Failed to export settings", color: "danger" });
    } finally {
      setExportLoading(false);
    }
  };

  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
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
      toast({ title: "Invalid JSON — check the pasted content", color: "danger" });
      return;
    }
    setPreviewLoading(true);
    try {
      const res = await apiClient.post("/admin/api/settings/import/preview", parsed);
      setPreviewData(res.data.data as PreviewResponse);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      toast({ title: axiosErr.response?.data?.error_description ?? "Preview failed", color: "danger" });
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleApply = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(backupText);
    } catch {
      toast({ title: "Invalid JSON", color: "danger" });
      return;
    }
    setApplyLoading(true);
    try {
      await apiClient.post("/admin/api/settings/import/apply", parsed);
      toast({ title: "Settings imported successfully", color: "success" });
      setPreviewData(null);
      setBackupText("");
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      toast({ title: axiosErr.response?.data?.error_description ?? "Import failed", color: "danger" });
    } finally {
      setApplyLoading(false);
    }
  };

  const handleTestSmtp = async () => {
    setTestingSmtp(true);
    try {
      await apiClient.post("/admin/api/settings/test-smtp");
      toast({ title: "Test email sent — check your inbox", color: "success" });
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      toast({ title: axiosErr.response?.data?.error_description ?? "Failed to send test email", color: "danger" });
    } finally {
      setTestingSmtp(false);
    }
  };

  useEffect(() => {
    if (settings) reset(settings);
  }, [settings, reset]);

  const onSubmit = async (values: SettingsValues) => {
    try {
      const processed: Record<string, string> = {};
      Object.entries(values).forEach(([k, v]) => {
        if (v === true) processed[k] = "true";
        else if (v === false) processed[k] = "false";
        else if (v !== undefined && v !== null) processed[k] = String(v);
      });

      await updateSettings.mutateAsync(processed);
      toast({ title: "Settings updated successfully", color: "success" });
    } catch {
      toast({ title: "Failed to update settings", color: "danger" });
    }
  };

  const onInvalid = (errors: FieldErrors<SettingsValues>) => {
    const name = Object.keys(errors)[0];
    const panel = name ? document.getElementsByName(name)[0]?.closest('[role="tabpanel"]') : null;
    const tab = panel ? document.getElementById(panel.getAttribute("aria-labelledby") ?? "")?.dataset.value : undefined;
    if (tab) setActiveTab(tab);
    if (name) requestAnimationFrame(() => form.setFocus(name));
    toast({ title: "Fix the highlighted fields before saving", color: "danger" });
  };

  const previewColumns = useMemo(() => {
    const col = dataColumns<PreviewRow>();
    return col.columns([
      col.accessor("key", {
        header: "Setting",
        meta: { width: "35%" },
        cell: (info) => (
          <Text as="code" textStyle="code">
            {info.getValue()}
          </Text>
        ),
      }),
      col.accessor("current", {
        header: "Current Value",
        meta: { width: "32%" },
        cell: (info) => (
          <Text textStyle="caption" muted>
            <EmptyValue value={info.getValue()} />
          </Text>
        ),
      }),
      col.accessor("incoming", {
        header: "New Value",
        meta: { width: "32%" },
        cell: ({ row, getValue }) => {
          const changed = row.original.current !== row.original.incoming;
          return (
            <Text textStyle={changed ? "label" : "caption"} color={changed ? "warning" : undefined}>
              <EmptyValue value={getValue()} />
            </Text>
          );
        },
      }),
    ]);
  }, []);

  if (isLoading)
    return (
      <div className="page-loading">
        <Spinner size="lg" label="Loading" />
      </div>
    );
  if (error) return <Alert color="danger" title="Failed to load settings" />;

  return (
    <FormProvider {...form}>
      <form onSubmit={handleSubmit(onSubmit, onInvalid)} noValidate>
        <Stack gap="md">

          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <Tabs.List aria-label="Settings sections">
              <Tabs.Trigger value="1">Login & Registration</Tabs.Trigger>
              <Tabs.Trigger value="2">MFA & Trusted Devices</Tabs.Trigger>
              <Tabs.Trigger value="3">Sessions & Tokens</Tabs.Trigger>
              <Tabs.Trigger value="4">Security</Tabs.Trigger>
              <Tabs.Trigger value="5">SMTP</Tabs.Trigger>
              <Tabs.Trigger value="6">Profile Fields</Tabs.Trigger>
              <Tabs.Trigger value="7">Branding</Tabs.Trigger>
              <Tabs.Trigger value="8">Backup</Tabs.Trigger>
            </Tabs.List>

            <Tabs.Panel value="1">
              <Stack gap="md" className="settings-tab">
                <SelectSetting name="auth_mode" label="Authentication Mode" options={AUTH_MODE_OPTIONS} />
                {authModeDescriptions[authModeKey] && dirtyFields.auth_mode && (
                  <Alert color="info" title={authModeDescriptions[authModeKey]} />
                )}

                <SelectSetting name="profile_field_email" label="Email Field Behavior" options={EMAIL_FIELD_OPTIONS} />
                {profileFieldEmail === "is_username" && dirtyFields.profile_field_email && (
                  <Alert color="warning" title="Compatibility warning">
                    When enabled, the username field is replaced by the email field. Existing users must have valid email addresses as
                    their usernames for login to work. Users with non-email usernames will be unable to log in.
                  </Alert>
                )}

                <CheckSetting name="allow_self_signup" label="Allow Self Signup" />
                <CheckSetting name="allow_username_change" label="Allow Username Change" />
                <CheckSetting name="allow_email_change" label="Allow Email Change" />
                <CheckSetting name="allow_self_service_deletion" label="Allow Self-Service Deletion" />

                <Divider />

                <Section title="Email Verification">
                  <CheckSetting name="require_email_verification" label="Require Email Verification" />
                  {emailVerifyWithoutSmtp && (
                    <Alert color="warning" title="SMTP not configured">
                      Email verification requires a configured SMTP server. Go to the SMTP tab to set it up.
                    </Alert>
                  )}
                  <DurationSetting name="email_verification_expiration" label="Verification Link Expiration" />
                </Section>

                <Divider />

                <Section title="Magic Link Login">
                  <CheckSetting name="magic_link_enabled" label="Magic Link Enabled" />
                  {magicLinkWithoutSmtp && (
                    <Alert color="warning" title="SMTP not configured">
                      Magic link login requires a configured SMTP server. Make sure SMTP is properly configured.
                    </Alert>
                  )}
                  <DurationSetting name="magic_link_expiration" label="Magic Link Expiration" />
                </Section>

                <Divider />

                <Section title="Passkeys">
                  <TextSetting name="passkey_rp_name" label="Passkey RP Name" />
                  <SelectSetting name="passkey_login_mode" label="Passkey Login Mode" options={PASSKEY_LOGIN_MODE_OPTIONS} />
                  {passkeyLoginModeDescriptions[passkeyLoginModeKey] && dirtyFields.passkey_login_mode && (
                    <Alert color="info" title={passkeyLoginModeDescriptions[passkeyLoginModeKey]} />
                  )}
                  {passkeyModeWithoutPasskeys && (
                    <Alert color="warning" title="Passkey login is disabled">
                      Authentication Mode is set to Password Only. Set it to Password & Passkey or Passkey Only for this setting to
                      take effect.
                    </Alert>
                  )}
                  {passkeyOnlyWithPasswordFallback && (
                    <Alert color="info" title="Password login is still enabled">
                      The username field will remain visible for password fallback. Set Authentication Mode to Passkey Only to fully
                      hide it.
                    </Alert>
                  )}
                </Section>
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="2">
              <Stack gap="md" className="settings-tab">
                <CheckSetting name="require_mfa" label="Require MFA" />
                <SelectSetting name="mfa_method" label="MFA Method" options={MFA_METHOD_OPTIONS} />
                {emailMfaWithoutSmtp && (
                  <Alert color="warning" title="SMTP not configured">
                    Email OTP requires a configured SMTP server. Go to the SMTP tab to set it up, otherwise email MFA will fail at
                    login.
                  </Alert>
                )}

                <Divider />

                <Section title="Trusted Devices">
                  <CheckSetting name="trust_device_enabled" label="Trust Device Enabled" />
                  <DurationSetting name="trust_device_expiration" label="Trust Device Expiration" />
                </Section>
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="3">
              <Stack gap="md" className="settings-tab">
                <Section title="SSO Sessions">
                  <CheckSetting name="sso_enabled" label="SSO Enabled" />
                  <DurationSetting name="sso_session_idle_timeout" label="SSO Session Idle Timeout" />
                  <DurationSetting name="sso_session_max_age" label="SSO Session Max Age" />
                </Section>

                <Divider />

                <Section title="Token Expiration">
                  <DurationSetting name="access_token_expiration" label="Access Token" />
                  <DurationSetting name="refresh_token_expiration" label="Refresh Token" />
                  <DurationSetting name="authorization_code_expiration" label="Auth Code" />
                </Section>

                <Divider />

                <Section title="Custom Claims">
                  <CheckSetting name="merge_group_claims" label="Merge Group Claims" />
                </Section>
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="4">
              <Stack gap="md" className="settings-tab">
                <Section title="User Validation">
                  <Inline gap="lg" align="start">
                    <NumberSetting name="validation_min_username_length" label="Min Username" min={1} />
                    <NumberSetting name="validation_max_username_length" label="Max Username" min={1} />
                  </Inline>
                  <Inline gap="lg" align="start">
                    <NumberSetting name="validation_min_password_length" label="Min Password" min={1} />
                    <NumberSetting name="validation_max_password_length" label="Max Password" min={1} />
                  </Inline>
                </Section>

                <Divider />

                <Section title="Account Lockout">
                  <NumberSetting name="account_lockout_max_attempts" label="Max Failed Attempts" min={0} />
                  <DurationSetting name="account_lockout_duration" label="Lockout Duration" />
                </Section>

                <Divider />

                <Section title="PKCE">
                  <CheckSetting name="pkce_enforce_s256" label="Enforce S256 Code Challenge" />
                  {(pkceEnforced === false || pkceEnforced === "false") && (
                    <Alert color="warning" title="Security Warning">
                      Clients may now use{" "}
                      <Text as="code" textStyle="code">
                        code_challenge_method=plain
                      </Text>
                      , which provides no security benefit — the verifier equals the challenge and is visible in the authorization
                      request. Only disable for backward compatibility with legacy clients that cannot support S256 (RFC 7636).
                    </Alert>
                  )}
                </Section>

                <Divider />

                <Section title="Audit Log">
                  <FormField control={control} name="audit_log_retention" label="Audit Log Retention" tooltip={tip("audit_log_retention")}>
                    {(field) => <RetentionInput value={asText(field.value)} onChange={field.onChange} onBlur={field.onBlur} />}
                  </FormField>
                </Section>
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="5">
              <Stack gap="md" className="settings-tab">
                <TextSetting name="smtp_host" label="SMTP Host" placeholder="smtp.example.com" />
                <TextSetting name="smtp_port" label="SMTP Port" placeholder="587" />
                <TextSetting name="smtp_username" label="SMTP Username" autoComplete="off" />
                <TextSetting name="smtp_password" label="SMTP Password" placeholder="Leave empty to keep current" password />
                <TextSetting name="smtp_from" label="SMTP From Address" placeholder="noreply@example.com" />
                <Inline>
                  <Button variant="outline" color="neutral" onClick={handleTestSmtp} loading={testingSmtp} disabled={!smtpHost}>
                    Send Test Email
                  </Button>
                </Inline>
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="6">
              <Stack gap="md" className="settings-tab">
                <Text muted>
                  Control which profile fields are shown on the signup form and the self-service account portal.{" "}
                  <strong>Hidden</strong> fields are never displayed. <strong>Optional</strong> fields are shown but not required.{" "}
                  <strong>Required</strong> fields must be filled during regular signup.
                </Text>

                <CheckSetting name="signup_show_optional_fields" label="Show Optional Fields on Signup" />
                <CheckSetting name="federation_copy_name_claims" label="Copy Names on Federated Signup" />

                <Divider />

                {PROFILE_FIELDS.map(([name, label]) => (
                  <SelectSetting key={name} name={name} label={label} options={VISIBILITY_OPTIONS} />
                ))}
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="7">
              <Stack gap="md" className="settings-tab">
                <Text muted>
                  Customize the appearance of login, signup, account pages, and transactional emails. Set a page title, logo, brand
                  color, and tagline. Use custom CSS to further match your brand. Footer links appear below the login form and in
                  emails. Changes apply to all user-facing pages and emails served by the identity provider.
                </Text>

                <TextSetting name="theme_title" label="Page Title" />
                <TextSetting name="theme_logo_url" label="Logo URL" placeholder="https://..." />
                <TextareaSetting
                  name="theme_css_inline"
                  label="Custom CSS"
                  rows={8}
                  code
                  placeholder=":root { --color-primary-bg: #ff7b00; }"
                />
                <TextSetting name="theme_brand_color" label="Brand Color" placeholder="#18181b" />
                <TextSetting name="theme_tagline" label="Tagline" placeholder="Simple. Safe. Self-hosted." />
                <TextareaSetting
                  name="email_footer_text"
                  label="Email Footer Text"
                  rows={3}
                  placeholder={"Copyright 2026 Acme Corp.\n123 Main Street, Springfield"}
                />

                <Divider />

                <Controller
                  control={control}
                  name="footer_links"
                  render={({ field }) => (
                    <FieldGroup label="Footer Links" tooltip={tip("footer_links")}>
                      <FooterLinksEditor value={asText(field.value)} onChange={field.onChange} />
                    </FieldGroup>
                  )}
                />

                <Divider />

                <TextSetting
                  name="logout_success_url"
                  label="Signed-Out Page Link"
                  placeholder="/account/"
                  rules={{ validate: validateLogoutUrl }}
                />
                <TextSetting
                  name="logout_success_label"
                  label="Signed-Out Page Link Label"
                  placeholder="Go to your profile"
                  rules={{ maxLength: { value: 100, message: "At most 100 characters" } }}
                />
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="8">
              <Stack gap="md" className="settings-tab">
                <Stack gap="sm">
                  <Heading level={3} textStyle="subheading">
                    Export
                  </Heading>
                  <Text muted>Download all settings as a JSON file.</Text>
                  <Inline>
                    <Button variant="outline" color="neutral" startIcon={<IconDownload />} loading={exportLoading} onClick={handleExport}>
                      Download Settings
                    </Button>
                  </Inline>
                </Stack>

                <Divider />

                <Stack gap="sm">
                  <Heading level={3} textStyle="subheading">
                    Import
                  </Heading>
                  <Text muted>Paste a settings JSON file below or upload one. Preview changes before applying.</Text>
                  <Inline>
                    <input type="file" accept=".json,application/json" ref={fileInputRef} hidden onChange={handleFileUpload} />
                    <Button
                      variant="outline"
                      color="neutral"
                      startIcon={<IconUpload />}
                      onClick={() => fileInputRef.current?.click()}
                    >
                      Upload File
                    </Button>
                  </Inline>
                  <Textarea
                    className="settings-code"
                    aria-label="Settings JSON"
                    value={backupText}
                    onChange={(e) => {
                      setBackupText(e.target.value);
                      setPreviewData(null);
                    }}
                    placeholder="Paste settings JSON here or upload a file…"
                    rows={8}
                  />
                  <Inline gap="sm" justify="end">
                    <Button
                      variant="outline"
                      color="neutral"
                      onClick={handlePreview}
                      loading={previewLoading}
                      disabled={!backupText.trim()}
                    >
                      Preview Import
                    </Button>
                    {previewData && (
                      <Button onClick={handleApply} loading={applyLoading}>
                        Apply Import
                      </Button>
                    )}
                  </Inline>
                </Stack>

                {previewData && (
                  <>
                    {previewData.unknown.length > 0 && (
                      <Alert color="warning" title="Unknown keys will be skipped">
                        <Inline gap="xs">
                          {previewData.unknown.map((k) => (
                            <Badge key={k} variant="soft" color="neutral">
                              {k}
                            </Badge>
                          ))}
                        </Inline>
                      </Alert>
                    )}
                    <DataTable
                      caption="Import preview"
                      data={previewData.rows}
                      columns={previewColumns}
                      getRowId={(row) => row.key}
                      pageSize={false}
                      emptyTitle="No settings in this file"
                    />
                  </>
                )}
              </Stack>
            </Tabs.Panel>
          </Tabs>

          {activeTab !== "8" && (
            <Inline justify="end" className="settings-save-bar">
              <Button type="submit" size="md" startIcon={<IconDeviceFloppy />} loading={updateSettings.isPending}>
                Save All Settings
              </Button>
            </Inline>
          )}
        </Stack>
      </form>
    </FormProvider>
  );
}
