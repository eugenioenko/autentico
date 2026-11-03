import { IconInfoCircle } from "@tabler/icons-react";
import { Field, Tooltip } from "@yarcl/react";
import type { ReactNode } from "react";
import {
  Controller,
  type Control,
  type ControllerRenderProps,
  type FieldPath,
  type FieldValues,
  type RegisterOptions,
} from "react-hook-form";

export function InfoTip({ content }: { content: ReactNode }) {
  return (
    <Tooltip content={content}>
      <span className="field-tip" tabIndex={0} role="img" aria-label="More information">
        <IconInfoCircle aria-hidden="true" />
      </span>
    </Tooltip>
  );
}

interface FormFieldProps<T extends FieldValues, N extends FieldPath<T>> {
  control: Control<T>;
  name: N;
  label: ReactNode;
  tooltip?: ReactNode;
  description?: ReactNode;
  rules?: Omit<RegisterOptions<T, N>, "valueAsNumber" | "valueAsDate" | "setValueAs" | "disabled">;
  children: (field: ControllerRenderProps<T, N>) => ReactNode;
}

export function FormField<T extends FieldValues, N extends FieldPath<T>>({
  control,
  name,
  label,
  tooltip,
  description,
  rules,
  children,
}: FormFieldProps<T, N>) {
  return (
    <Controller
      control={control}
      name={name}
      rules={rules}
      render={({ field, fieldState }) => (
        <Field
          label={label}
          labelEnd={tooltip ? <InfoTip content={tooltip} /> : undefined}
          description={description}
          error={fieldState.error?.message}
          required={!!rules?.required}
        >
          {children(field)}
        </Field>
      )}
    />
  );
}
