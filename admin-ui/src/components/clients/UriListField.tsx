import type { ReactNode } from "react";
import { Controller, useFieldArray, useFormState, type Control } from "react-hook-form";
import { Button, IconButton, Input, Stack, Text } from "@yarcl/react";
import { IconCircleMinus, IconPlus } from "@tabler/icons-react";
import FieldGroup from "../FieldGroup";
import { urlRule } from "../../lib/validation";
import type { ClientFormValues } from "./clientForm";

interface UriListFieldProps {
  control: Control<ClientFormValues>;
  name: "redirect_uris" | "post_logout_redirect_uris";
  label: string;
  itemLabel: string;
  addLabel: string;
  tooltip: ReactNode;
  placeholder?: string;
  requiredMessage?: string;
}

export default function UriListField({
  control,
  name,
  label,
  itemLabel,
  addLabel,
  tooltip,
  placeholder,
  requiredMessage,
}: UriListFieldProps) {
  const { fields, append, remove } = useFieldArray({
    control,
    name,
    rules: requiredMessage ? { validate: (items) => items.length > 0 || requiredMessage } : undefined,
  });
  const { errors } = useFormState({ control, name });
  const canRemove = !requiredMessage || fields.length > 1;

  return (
    <FieldGroup label={label} tooltip={tooltip} required={!!requiredMessage} error={errors[name]?.root?.message}>
      <Stack>
        {fields.map((item, index) => (
          <Controller
            key={item.id}
            control={control}
            name={`${name}.${index}.value`}
            rules={{ required: "URI is required", pattern: urlRule() }}
            render={({ field, fieldState }) => (
              <Stack gap="xs">
                <Input
                  {...field}
                  aria-label={`${itemLabel} ${index + 1}`}
                  aria-invalid={fieldState.error ? true : undefined}
                  placeholder={placeholder}
                  endContent={
                    canRemove ? (
                      <IconButton
                        variant="ghost"
                        color="neutral"
                        aria-label={`Remove ${itemLabel.toLowerCase()} ${index + 1}`}
                        onClick={() => remove(index)}
                      >
                        <IconCircleMinus />
                      </IconButton>
                    ) : undefined
                  }
                />
                {fieldState.error && (
                  <Text textStyle="caption" color="danger">
                    {fieldState.error.message}
                  </Text>
                )}
              </Stack>
            )}
          />
        ))}
        <Button variant="outline" color="neutral" startIcon={<IconPlus />} onClick={() => append({ value: "" })}>
          {addLabel}
        </Button>
      </Stack>
    </FieldGroup>
  );
}
