import { useId, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { Accordion, Alert, Button, Combobox, Dialog, Divider, Drawer, Input, Select, Stack, Text, toast } from "@yarcl/react";
import { IconCopy } from "@tabler/icons-react";
import { useCreateClient } from "../../hooks/useClients";
import type { ClientResponse } from "../../types/client";
import { FormField } from "../FormField";
import PasswordInput from "../PasswordInput";
import CopyText from "../CopyText";
import { tip } from "./clientTips";
import AccountAppFields from "./AccountAppFields";
import ClientOverrideFields from "./ClientOverrideFields";
import UriListField from "./UriListField";
import {
  CLIENT_TYPE_OPTIONS,
  GRANT_TYPE_OPTIONS,
  RESPONSE_TYPE_OPTIONS,
  SCOPE_OPTIONS,
  authMethodOptions,
  toClientRequest,
  type ClientFormValues,
} from "./clientForm";

interface ClientCreateFormProps {
  open: boolean;
  onClose: () => void;
}

const DEFAULTS: ClientFormValues = {
  client_name: "",
  client_type: "public",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
  scopes: ["openid", "profile", "email", "offline_access"],
  redirect_uris: [{ value: "" }],
  post_logout_redirect_uris: [],
};

export default function ClientCreateForm({ open, onClose }: ClientCreateFormProps) {
  const formId = useId();
  const { control, handleSubmit, reset, setValue } = useForm<ClientFormValues>({ defaultValues: DEFAULTS });
  const clientType = useWatch({ control, name: "client_type" }) ?? "public";
  const createClient = useCreateClient();
  const [secretModal, setSecretModal] = useState<ClientResponse | null>(null);

  const onSubmit = async (values: ClientFormValues) => {
    try {
      const result = await createClient.mutateAsync(toClientRequest(values));
      reset(DEFAULTS);
      onClose();
      if (result.client_secret) {
        setSecretModal(result);
      } else {
        toast({ title: "Client created successfully", color: "success" });
      }
    } catch {
      toast({ title: "Failed to create client", color: "danger" });
    }
  };

  const handleCopySecret = async () => {
    if (!secretModal?.client_secret) return;
    try {
      await navigator.clipboard.writeText(secretModal.client_secret);
      toast({ title: "Secret copied to clipboard", color: "success" });
    } catch {
      toast({ title: "Could not copy", color: "danger" });
    }
  };

  return (
    <>
      <Drawer
        title="Create Client"
        open={open}
        onOpenChange={(next) => !next && onClose()}
        side="right"
        size="md"
        footer={
          <>
            <Button variant="ghost" color="neutral" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" form={formId} loading={createClient.isPending}>
              Create
            </Button>
          </>
        }
      >
        <form id={formId} onSubmit={handleSubmit(onSubmit)} noValidate>
          <Stack gap="md">
            <FormField
              control={control}
              name="client_name"
              label="Client Name"
              tooltip={tip("client_name")}
              rules={{ required: "Client name is required" }}
            >
              {(field) => <Input {...field} placeholder="My Application" />}
            </FormField>

            <FormField control={control} name="client_id" label="Client ID" tooltip={tip("client_id")}>
              {(field) => <Input {...field} value={field.value ?? ""} placeholder="my-custom-client-id" autoComplete="off" />}
            </FormField>

            <FormField control={control} name="client_type" label="Client Type" tooltip={tip("client_type")}>
              {(field) => (
                <Select
                  options={CLIENT_TYPE_OPTIONS}
                  value={field.value ?? null}
                  onBlur={field.onBlur}
                  onValueChange={(value) => {
                    field.onChange(value ?? "public");
                    setValue("token_endpoint_auth_method", value === "public" ? "none" : "client_secret_basic");
                    if (value === "public") setValue("client_secret", undefined);
                  }}
                />
              )}
            </FormField>

            {clientType === "confidential" && (
              <FormField control={control} name="client_secret" label="Client Secret" tooltip={tip("client_secret")}>
                {(field) => <PasswordInput {...field} value={field.value ?? ""} placeholder="Auto-generated if left empty" />}
              </FormField>
            )}

            <UriListField
              control={control}
              name="redirect_uris"
              label="Redirect URIs"
              itemLabel="Redirect URI"
              addLabel="Add Redirect URI"
              tooltip={tip("redirect_uris")}
              placeholder="https://example.com/callback"
              requiredMessage="At least one redirect URI required"
            />

            <UriListField
              control={control}
              name="post_logout_redirect_uris"
              label="Post-Logout Redirect URIs"
              itemLabel="Post-logout redirect URI"
              addLabel="Add Post-Logout Redirect URI"
              tooltip={tip("post_logout_redirect_uris")}
              placeholder="https://example.com/logout-callback"
            />

            <FormField control={control} name="grant_types" label="Grant Types" tooltip={tip("grant_types")}>
              {(field) => (
                <Combobox multiple options={GRANT_TYPE_OPTIONS} value={field.value ?? []} onValueChange={field.onChange} onBlur={field.onBlur} />
              )}
            </FormField>

            <FormField control={control} name="response_types" label="Response Types" tooltip={tip("response_types")}>
              {(field) => (
                <Combobox multiple options={RESPONSE_TYPE_OPTIONS} value={field.value ?? []} onValueChange={field.onChange} onBlur={field.onBlur} />
              )}
            </FormField>

            <FormField control={control} name="scopes" label="Scopes" tooltip={tip("scopes")}>
              {(field) => (
                <Combobox
                  multiple
                  allowCustomValue
                  options={SCOPE_OPTIONS}
                  placeholder="Select or type scopes..."
                  value={field.value ?? []}
                  onValueChange={field.onChange}
                  onBlur={field.onBlur}
                />
              )}
            </FormField>

            <FormField
              control={control}
              name="token_endpoint_auth_method"
              label="Token Endpoint Auth Method"
              tooltip={tip("token_endpoint_auth_method")}
            >
              {(field) => (
                <Select
                  options={authMethodOptions(clientType)}
                  value={field.value ?? null}
                  onValueChange={(v) => field.onChange(v ?? undefined)}
                  onBlur={field.onBlur}
                />
              )}
            </FormField>

            <Divider />

            <Accordion type="multiple">
              <Accordion.Item value="overrides">
                <Accordion.Trigger>Configuration Overrides</Accordion.Trigger>
                <Accordion.Content>
                  <ClientOverrideFields control={control} />
                </Accordion.Content>
              </Accordion.Item>
              <Accordion.Item value="account_app">
                <Accordion.Trigger>Account Dashboard</Accordion.Trigger>
                <Accordion.Content>
                  <AccountAppFields control={control} />
                </Accordion.Content>
              </Accordion.Item>
            </Accordion>
          </Stack>
        </form>
      </Drawer>

      <Dialog
        title="Client Created Successfully"
        open={!!secretModal}
        onOpenChange={(next) => !next && setSecretModal(null)}
        size="md"
        footer={
          <>
            <Button variant="outline" color="neutral" startIcon={<IconCopy />} onClick={handleCopySecret}>
              Copy Secret
            </Button>
            <Button onClick={() => setSecretModal(null)}>Done</Button>
          </>
        }
      >
        <Stack gap="md">
          <Alert color="warning" title="Save this secret now. It will not be shown again." />
          <Stack gap="xs">
            <Text textStyle="label">Client ID:</Text>
            <CopyText text={secretModal?.client_id ?? ""} code />
          </Stack>
          <Stack gap="xs">
            <Text textStyle="label">Client Secret:</Text>
            <CopyText text={secretModal?.client_secret ?? ""} code />
          </Stack>
        </Stack>
      </Dialog>
    </>
  );
}
