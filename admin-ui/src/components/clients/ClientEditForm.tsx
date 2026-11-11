import { useEffect, useId } from "react";
import { useForm, useWatch } from "react-hook-form";
import { Accordion, Alert, Button, Combobox, Divider, Drawer, Field, Input, Select, Stack, Switch, toast } from "@yarcl/react";
import { useUpdateClient } from "../../hooks/useClients";
import type { ClientInfoResponse } from "../../types/client";
import { FormField, InfoTip } from "../FormField";
import { tip } from "./clientTips";
import AccountAppFields from "./AccountAppFields";
import ClientOverrideFields from "./ClientOverrideFields";
import ClientAccessFields, { BuiltinAccessNotice } from "./ClientAccessFields";
import UriListField from "./UriListField";
import {
  GRANT_TYPE_OPTIONS,
  RESPONSE_TYPE_OPTIONS,
  SCOPE_OPTIONS,
  authMethodOptions,
  isBuiltinClient,
  toClientRequest,
  toUriItems,
  type ClientFormValues,
} from "./clientForm";

interface ClientEditFormProps {
  open: boolean;
  client: ClientInfoResponse | null;
  onClose: () => void;
}

const EMPTY: ClientFormValues = {
  client_name: "",
  redirect_uris: [],
  post_logout_redirect_uris: [],
  grant_types: [],
  response_types: [],
  scopes: [],
};

function toFormValues(client: ClientInfoResponse): ClientFormValues {
  return {
    client_name: client.client_name ?? "",
    is_active: client.is_active,
    redirect_uris: toUriItems(client.redirect_uris),
    post_logout_redirect_uris: toUriItems(client.post_logout_redirect_uris),
    grant_types: client.grant_types ?? [],
    response_types: client.response_types ?? [],
    scopes: client.scopes?.split(" ").filter(Boolean) ?? [],
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    access_token_expiration: client.access_token_expiration,
    refresh_token_expiration: client.refresh_token_expiration,
    authorization_code_expiration: client.authorization_code_expiration,
    allowed_audiences: client.allowed_audiences,
    allow_self_signup: client.allow_self_signup,
    sso_session_idle_timeout: client.sso_session_idle_timeout,
    trust_device_enabled: client.trust_device_enabled,
    trust_device_expiration: client.trust_device_expiration,
    consent_required: client.consent_required,
    show_in_account: client.show_in_account,
    client_uri: client.client_uri,
    logo_uri: client.logo_uri,
    description: client.description,
    restrict_access: client.restrict_access ?? false,
    allowed_groups: client.allowed_groups ?? [],
    allowed_users: client.allowed_users ?? [],
  };
}

export default function ClientEditForm({ open, client, onClose }: ClientEditFormProps) {
  const formId = useId();
  const { control, handleSubmit, reset } = useForm<ClientFormValues>({ defaultValues: EMPTY });
  const isActive = useWatch({ control, name: "is_active" });
  const updateClient = useUpdateClient();
  const builtin = isBuiltinClient(client?.client_id);
  const hasLegacyResponseTypes = client?.response_types?.some((value) => value !== "code") ?? false;

  useEffect(() => {
    if (client && open) reset(toFormValues(client));
  }, [client, open, reset]);

  const onSubmit = async (values: ClientFormValues) => {
    if (!client?.client_id) return;
    try {
      await updateClient.mutateAsync({ clientId: client.client_id, data: toClientRequest(values, builtin) });
      toast({ title: "Client updated successfully", color: "success" });
      onClose();
    } catch {
      toast({ title: "Failed to update client", color: "danger" });
    }
  };

  return (
    <Drawer
      title={`Edit Client: ${client?.client_name ?? ""}`}
      open={open}
      onOpenChange={(next) => !next && onClose()}
      side="right"
      size="md"
      footer={
        <>
          <Button variant="ghost" color="neutral" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form={formId} loading={updateClient.isPending}>
            Save
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
            {(field) => <Input {...field} />}
          </FormField>

          <Field label="Client ID" labelEnd={<InfoTip content={tip("client_id")} />}>
            <Input value={client?.client_id ?? ""} disabled readOnly />
          </Field>

          <FormField control={control} name="is_active" label="Status">
            {(field) => (
              <Switch
                name={field.name}
                ref={field.ref}
                checked={!!field.value}
                onChange={(e) => field.onChange(e.target.checked)}
                onBlur={field.onBlur}
              >
                {field.value ? "Active" : "Inactive"}
              </Switch>
            )}
          </FormField>

          {!isActive && <Alert color="warning" title="This client is disabled and will not be able to authenticate." />}

          <UriListField
            control={control}
            name="redirect_uris"
            label="Redirect URIs"
            itemLabel="Redirect URI"
            addLabel="Add Redirect URI"
            tooltip={tip("redirect_uris")}
            requiredMessage="At least one redirect URI required"
          />

          <UriListField
            control={control}
            name="post_logout_redirect_uris"
            label="Post-Logout Redirect URIs"
            itemLabel="Post-logout redirect URI"
            addLabel="Add Post-Logout Redirect URI"
            tooltip={tip("post_logout_redirect_uris")}
          />

          <FormField control={control} name="grant_types" label="Grant Types" tooltip={tip("grant_types")}>
            {(field) => (
              <Combobox multiple options={GRANT_TYPE_OPTIONS} value={field.value ?? []} onValueChange={field.onChange} onBlur={field.onBlur} />
            )}
          </FormField>

          <FormField
            control={control}
            name="response_types"
            label="Response Types"
            tooltip={tip("response_types")}
            description={
              hasLegacyResponseTypes
                ? "This client has unsupported response types. Remove them before saving. Select Code explicitly if this client should use Authorization Code responses."
                : undefined
            }
            rules={{
              validate: (values) => {
                if (values?.some((value) => value !== "code")) {
                  return "Only Code is supported. Remove unsupported response types before saving.";
                }
                if (hasLegacyResponseTypes && !values?.includes("code")) {
                  return "Select Code explicitly to replace the legacy response types.";
                }
                return true;
              },
            }}
          >
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
                options={authMethodOptions(client?.client_type)}
                value={field.value ?? null}
                onValueChange={(v) => field.onChange(v ?? undefined)}
                onBlur={field.onBlur}
              />
            )}
          </FormField>

          <Divider />

          <Accordion
            key={client?.client_id}
            type="multiple"
            defaultValue={client?.restrict_access && !builtin ? ["access"] : []}
          >
            <Accordion.Item value="access">
              <Accordion.Trigger>Access</Accordion.Trigger>
              <Accordion.Content>
                {builtin ? <BuiltinAccessNotice /> : <ClientAccessFields control={control} />}
              </Accordion.Content>
            </Accordion.Item>
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
  );
}
