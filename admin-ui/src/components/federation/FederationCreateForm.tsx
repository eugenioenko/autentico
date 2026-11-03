import { useId } from "react";
import { useForm, useWatch } from "react-hook-form";
import { Alert, Button, Drawer, Input, NumberInput, Stack, Switch, Text, Textarea, toast } from "@yarcl/react";
import { IconInfoCircle } from "@tabler/icons-react";
import { useCreateFederationProvider } from "../../hooks/useFederation";
import type { FederationProviderCreateRequest } from "../../types/federation";
import { FormField } from "../FormField";
import PasswordInput from "../PasswordInput";
import CopyText from "../CopyText";
import { urlRule } from "../../lib/validation";
import ClaimRequirementsField, { claimRequirementsError } from "./ClaimRequirementsField";

interface Props {
  open: boolean;
  onClose: () => void;
}

const DEFAULTS: FederationProviderCreateRequest = {
  id: "",
  name: "",
  issuer: "",
  client_id: "",
  client_secret: "",
  icon_svg: "",
  enabled: true,
  sort_order: 0,
  claim_requirements: [],
};

export default function FederationCreateForm({ open, onClose }: Props) {
  const formId = useId();
  const { control, handleSubmit, reset, setError } = useForm<FederationProviderCreateRequest>({ defaultValues: DEFAULTS });
  const slug = (useWatch({ control, name: "id" }) ?? "").trim();
  const createProvider = useCreateFederationProvider();

  const onSubmit = async (values: FederationProviderCreateRequest) => {
    const rulesError = await claimRequirementsError(values.claim_requirements);
    if (rulesError) {
      setError("claim_requirements", { message: rulesError });
      return;
    }
    try {
      await createProvider.mutateAsync(values);
      toast({ title: "Federation provider created", color: "success" });
      reset(DEFAULTS);
      onClose();
    } catch {
      toast({ title: "Failed to create federation provider", color: "danger" });
    }
  };

  const callbackURL = `${window.location.origin}/oauth2/federation/${slug || "{id}"}/callback`;

  return (
    <Drawer
      title="Add Federation Provider"
      open={open}
      onOpenChange={(next) => !next && onClose()}
      side="right"
      size="lg"
      footer={
        <>
          <Button variant="ghost" color="neutral" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form={formId} loading={createProvider.isPending}>
            Create
          </Button>
        </>
      }
    >
      <Stack gap="lg">
        <Alert color="info" icon={<IconInfoCircle />} title="How to set up a provider">
          <Stack gap="xs">
            <Text>
              Set a <strong>Provider ID</strong> below, register this redirect URI in your provider's console, then paste the
              credentials here.
            </Text>
            {slug ? <CopyText text={callbackURL} code /> : <Text textStyle="code">{callbackURL}</Text>}
          </Stack>
        </Alert>

        <form id={formId} onSubmit={handleSubmit(onSubmit)} noValidate>
          <Stack gap="md">
            <FormField
              control={control}
              name="id"
              label="Provider ID"
              description="URL-safe slug used in the redirect URI. Cannot be changed after creation."
              rules={{
                required: "Provider ID is required",
                pattern: { value: /^[a-z0-9-]+$/, message: "Only lowercase letters, numbers, and hyphens" },
              }}
            >
              {(field) => <Input {...field} placeholder="e.g. google, microsoft, okta" autoComplete="federation-provider-id" />}
            </FormField>

            <FormField control={control} name="name" label="Display Name" rules={{ required: "Name is required" }}>
              {(field) => <Input {...field} placeholder="Google" />}
            </FormField>

            <FormField
              control={control}
              name="issuer"
              label="Issuer URL"
              description="The OIDC discovery base URL (without /.well-known/openid-configuration)"
              rules={{ required: "Issuer is required", pattern: urlRule() }}
            >
              {(field) => <Input {...field} placeholder="https://accounts.google.com" />}
            </FormField>

            <FormField control={control} name="client_id" label="Client ID" rules={{ required: "Client ID is required" }}>
              {(field) => (
                <Input {...field} placeholder="123456789-abc.apps.googleusercontent.com" autoComplete="federation-client-id" />
              )}
            </FormField>

            <FormField control={control} name="client_secret" label="Client Secret" rules={{ required: "Client secret is required" }}>
              {(field) => <PasswordInput {...field} placeholder="Client secret from your provider" />}
            </FormField>

            <FormField
              control={control}
              name="icon_svg"
              label="Icon SVG"
              description="Paste SVG markup for the provider button icon (optional)."
            >
              {(field) => (
                <Textarea
                  {...field}
                  value={field.value ?? ""}
                  rows={3}
                  placeholder={'<svg xmlns="http://www.w3.org/2000/svg" ...>...</svg>'}
                />
              )}
            </FormField>

            <ClaimRequirementsField control={control} name="claim_requirements" />

            <FormField control={control} name="sort_order" label="Sort Order" description="Lower numbers appear first on the login page.">
              {(field) => (
                <NumberInput
                  name={field.name}
                  ref={field.ref}
                  min={0}
                  value={field.value ?? null}
                  onValueChange={(v) => field.onChange(v ?? undefined)}
                  onBlur={field.onBlur}
                />
              )}
            </FormField>

            <FormField control={control} name="enabled" label="Enabled">
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
          </Stack>
        </form>
      </Stack>
    </Drawer>
  );
}
