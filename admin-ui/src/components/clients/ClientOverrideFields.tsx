import type { ReactNode } from "react";
import type { Control } from "react-hook-form";
import { Combobox, Input, Stack, Switch } from "@yarcl/react";
import { FormField } from "../FormField";
import { overrideTip } from "./clientTips";
import type { ClientFormValues } from "./clientForm";

type TextName =
  | "access_token_expiration"
  | "refresh_token_expiration"
  | "authorization_code_expiration"
  | "sso_session_idle_timeout"
  | "trust_device_expiration";
type SwitchName = "allow_self_signup" | "trust_device_enabled" | "consent_required";

export default function ClientOverrideFields({ control }: { control: Control<ClientFormValues> }) {
  const text = (name: TextName, label: string, placeholder: string) => (
    <FormField control={control} name={name} label={label} tooltip={overrideTip(name)}>
      {(field) => <Input {...field} value={field.value ?? ""} placeholder={placeholder} />}
    </FormField>
  );
  const toggle = (name: SwitchName, label: string, tooltip: ReactNode = overrideTip(name)) => (
    <FormField control={control} name={name} label={label} tooltip={tooltip}>
      {(field) => (
        <Switch
          name={field.name}
          ref={field.ref}
          checked={!!field.value}
          onChange={(e) => field.onChange(e.target.checked)}
          onBlur={field.onBlur}
        />
      )}
    </FormField>
  );

  return (
    <Stack gap="md">
      {text("access_token_expiration", "Access Token Expiration", "Global default (e.g. 15m)")}
      {text("refresh_token_expiration", "Refresh Token Expiration", "Global default (e.g. 720h)")}
      {text("authorization_code_expiration", "Auth Code Expiration", "Global default (e.g. 10m)")}
      <FormField control={control} name="allowed_audiences" label="Allowed Audiences" tooltip={overrideTip("allowed_audiences")}>
        {(field) => (
          <Combobox
            multiple
            allowCustomValue
            options={[]}
            placeholder="Add audiences..."
            value={field.value ?? []}
            onValueChange={field.onChange}
            onBlur={field.onBlur}
          />
        )}
      </FormField>
      {toggle("allow_self_signup", "Allow Self Signup")}
      {text("sso_session_idle_timeout", "SSO Session Idle Timeout", "Global default (e.g. 30m)")}
      {toggle("trust_device_enabled", "Trust Device Enabled")}
      {text("trust_device_expiration", "Trust Device Expiration", "Global default (e.g. 720h)")}
      {toggle(
        "consent_required",
        "Consent Required",
        "When enabled, users must grant consent before this client can access their information",
      )}
    </Stack>
  );
}
