import { Controller, type Control, type FieldValues, type Path } from "react-hook-form";
import FieldGroup from "../FieldGroup";
import ClaimRequirementsEditor from "./ClaimRequirementsEditor";
import { validateClaimRequirements } from "../../api/federation";
import type { ClaimRequirement } from "../../types/federation";

export async function claimRequirementsError(rules: ClaimRequirement[] | undefined) {
  try {
    await validateClaimRequirements(undefined, rules);
    return null;
  } catch (err) {
    return err instanceof Error ? err.message : "Invalid claim requirements";
  }
}

interface ClaimRequirementsFieldProps<T extends FieldValues> {
  control: Control<T>;
  name: Path<T>;
  onEdit?: () => void;
}

export default function ClaimRequirementsField<T extends FieldValues>({ control, name, onEdit }: ClaimRequirementsFieldProps<T>) {
  return (
    <Controller
      control={control}
      name={name}
      render={({ field, fieldState }) => (
        <FieldGroup label="Claim requirements" error={fieldState.error?.message}>
          <ClaimRequirementsEditor
            value={field.value ?? []}
            onChange={(rules) => {
              field.onChange(rules);
              onEdit?.();
            }}
          />
        </FieldGroup>
      )}
    />
  );
}
