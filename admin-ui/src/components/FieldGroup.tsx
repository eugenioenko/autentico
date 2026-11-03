import { Inline, Stack, Text } from "@yarcl/react";
import { useId, type ReactNode } from "react";
import { InfoTip } from "./FormField";

interface FieldGroupProps {
  label: ReactNode;
  tooltip?: ReactNode;
  description?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  children: ReactNode;
}

export default function FieldGroup({ label, tooltip, description, error, required, children }: FieldGroupProps) {
  const id = useId();
  const descriptionId = description ? `${id}-description` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  return (
    <Stack
      gap="xs"
      role="group"
      aria-labelledby={`${id}-label`}
      aria-describedby={[descriptionId, errorId].filter(Boolean).join(" ") || undefined}
    >
      <Inline gap="xs" align="center">
        <Text as="span" id={`${id}-label`} textStyle="label">
          {label}
          {required && (
            <span className="yarcl-label-required" aria-hidden="true">
              {" *"}
            </span>
          )}
        </Text>
        {tooltip && <InfoTip content={tooltip} />}
      </Inline>
      {children}
      {description && (
        <Text id={descriptionId} textStyle="caption" muted>
          {description}
        </Text>
      )}
      {error && (
        <Text id={errorId} textStyle="caption" color="danger">
          {error}
        </Text>
      )}
    </Stack>
  );
}
