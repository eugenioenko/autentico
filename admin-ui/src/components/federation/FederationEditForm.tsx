import { useEffect, useId, useState } from "react";
import { useForm } from "react-hook-form";
import { Alert, Button, Drawer, Inline, Input, NumberInput, Stack, Switch, Text, Textarea, toast } from "@yarcl/react";
import { useUpdateFederationProvider } from "../../hooks/useFederation";
import type { FederationProvider, FederationProviderUpdateRequest } from "../../types/federation";
import { FormField } from "../FormField";
import PasswordInput from "../PasswordInput";
import CopyText from "../CopyText";
import { urlRule } from "../../lib/validation";
import ClaimRequirementsField, { claimRequirementsError } from "./ClaimRequirementsField";

interface Props {
  open: boolean;
  provider: FederationProvider | null;
  onClose: () => void;
}

const EMPTY: FederationProviderUpdateRequest = { name: "", issuer: "", client_id: "", claim_requirements: [] };

export default function FederationEditForm({ open, provider, onClose }: Props) {
  const formId = useId();
  const { control, handleSubmit, reset, setError, setValue } = useForm<FederationProviderUpdateRequest>({ defaultValues: EMPTY });
  const updateProvider = useUpdateFederationProvider();
  const [rulesTouched, setRulesTouched] = useState(false);

  useEffect(() => {
    if (provider) {
      setRulesTouched(false);
      reset({
        claim_requirements: provider.claim_requirements ?? [],
        name: provider.name,
        issuer: provider.issuer,
        client_id: provider.client_id,
        client_secret: "",
        icon_svg: provider.icon_svg,
        enabled: provider.enabled,
        sort_order: provider.sort_order,
      });
    }
  }, [provider, reset]);

  const onSubmit = async (values: FederationProviderUpdateRequest) => {
    if (!provider) return;
    const rulesError = await claimRequirementsError(values.claim_requirements);
    if (rulesError) {
      setError("claim_requirements", { message: rulesError });
      return;
    }
    const data = { ...values };
    if (provider.claim_requirements_error && !rulesTouched) delete data.claim_requirements;
    try {
      await updateProvider.mutateAsync({ id: provider.id, data });
      toast({ title: "Federation provider updated", color: "success" });
      onClose();
    } catch {
      toast({ title: "Failed to update federation provider", color: "danger" });
    }
  };

  const callbackURL = provider ? `${window.location.origin}/oauth2/federation/${provider.id}/callback` : "";

  return (
    <Drawer
      title="Edit Federation Provider"
      open={open}
      onOpenChange={(next) => !next && onClose()}
      side="right"
      size="lg"
      footer={
        <>
          <Button variant="ghost" color="neutral" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form={formId} loading={updateProvider.isPending}>
            Save
          </Button>
        </>
      }
    >
      <Stack gap="lg">
        {provider && (
          <Alert color="info" title="Redirect URI for this provider">
            <Stack gap="xs">
              <Text>Register this redirect URI in your identity provider's developer console:</Text>
              <CopyText text={callbackURL} code />
            </Stack>
          </Alert>
        )}

        {provider?.claim_requirements_error && (
          <Alert color="danger" title="Stored claim requirements are invalid">
            Login is blocked. Replace the requirements or explicitly clear them to repair this provider. Other edits preserve the
            invalid policy.
          </Alert>
        )}

        <form id={formId} onSubmit={handleSubmit(onSubmit)} noValidate>
          <Stack gap="md">
            <FormField control={control} name="name" label="Display Name" rules={{ required: "Name is required" }}>
              {(field) => <Input {...field} />}
            </FormField>

            <FormField control={control} name="issuer" label="Issuer URL" rules={{ required: "Issuer is required", pattern: urlRule() }}>
              {(field) => <Input {...field} />}
            </FormField>

            <FormField control={control} name="client_id" label="Client ID" rules={{ required: "Client ID is required" }}>
              {(field) => <Input {...field} />}
            </FormField>

            <FormField control={control} name="client_secret" label="Client Secret" description="Leave empty to keep the existing secret.">
              {(field) => <PasswordInput {...field} value={field.value ?? ""} placeholder="Leave empty to keep unchanged" />}
            </FormField>

            <FormField control={control} name="icon_svg" label="Icon SVG">
              {(field) => <Textarea {...field} value={field.value ?? ""} rows={3} />}
            </FormField>

            <ClaimRequirementsField control={control} name="claim_requirements" onEdit={() => setRulesTouched(true)} />
            {provider?.claim_requirements_error && (
              <Inline>
                <Button
                  variant="outline"
                  color="neutral"
                  onClick={() => {
                    setValue("claim_requirements", []);
                    setRulesTouched(true);
                  }}
                >
                  Clear invalid requirements
                </Button>
              </Inline>
            )}

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
