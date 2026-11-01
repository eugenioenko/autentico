import type { Control } from "react-hook-form";
import { Input, Stack, Switch, Textarea } from "@yarcl/react";
import { FormField } from "../FormField";
import { appTip } from "./clientTips";
import type { ClientFormValues } from "./clientForm";

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

function validateWebUri(value?: string) {
  if (!value) return true;
  try {
    const u = new URL(value);
    if (u.username || u.password) throw new Error();
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && LOOPBACK_HOSTS.includes(u.hostname)) return true;
  } catch {
    return "Must be a valid URL";
  }
  return "Must use https (http is only allowed for localhost)";
}

export default function AccountAppFields({ control }: { control: Control<ClientFormValues> }) {
  return (
    <Stack gap="md">
      <FormField control={control} name="show_in_account" label="Show in Account Dashboard" tooltip={appTip("show_in_account")}>
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

      <FormField
        control={control}
        name="client_uri"
        label="Application URL"
        tooltip={appTip("client_uri")}
        rules={{ validate: validateWebUri }}
      >
        {(field) => <Input {...field} value={field.value ?? ""} placeholder="https://app.example.com" />}
      </FormField>

      <FormField
        control={control}
        name="logo_uri"
        label="Logo URL"
        tooltip={appTip("logo_uri")}
        rules={{ validate: validateWebUri }}
      >
        {(field) => <Input {...field} value={field.value ?? ""} placeholder="https://app.example.com/logo.png" />}
      </FormField>

      <FormField
        control={control}
        name="description"
        label="Description"
        tooltip={appTip("description")}
        rules={{
          maxLength: { value: 1000, message: "At most 1000 characters" },
          pattern: { value: /^[^<>]*$/, message: "Must not contain < or >" },
        }}
      >
        {(field) => <Textarea {...field} value={field.value ?? ""} rows={2} />}
      </FormField>
    </Stack>
  );
}
