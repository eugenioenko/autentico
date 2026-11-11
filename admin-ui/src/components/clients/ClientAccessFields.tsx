import { useWatch, type Control } from "react-hook-form";
import { Alert, Combobox, Stack, Switch, Text } from "@yarcl/react";
import { FormField } from "../FormField";
import { useGroups, useGroupsByIds } from "../../hooks/useGroups";
import { useUsers, useUsersByIds } from "../../hooks/useUsers";
import { useDebouncedState } from "../../hooks/useDebouncedState";
import { accessTip } from "./clientTips";
import type { ClientFormValues } from "./clientForm";

interface SelectProps {
  value: string[];
  onChange: (value: string[]) => void;
  onBlur: () => void;
  disabled: boolean;
}

const contains = (label: string, text: string) => label.toLowerCase().includes(text.trim().toLowerCase());

function GroupSelect({ value, onChange, onBlur, disabled }: SelectProps) {
  const [search, setSearch] = useDebouncedState("", 300);
  const { data: searchData, isFetching } = useGroups({ limit: 20, sort: "name", order: "asc", search: search || undefined });
  const selectedGroups = useGroupsByIds(value);

  const searchIds = new Set((searchData?.items ?? []).map((g) => g.id));
  const options = [
    ...(searchData?.items ?? []),
    ...selectedGroups.filter((g) => !searchIds.has(g.id)),
  ].map((g) => ({ value: g.id, label: g.name }));

  return (
    <Combobox
      multiple
      placeholder={disabled ? undefined : "Search groups..."}
      options={options}
      filter={(option, text) => searchIds.has(option.value) || contains(option.label, text)}
      loading={isFetching}
      value={value}
      onValueChange={onChange}
      onInputValueChange={(text) => setSearch(text)}
      onBlur={onBlur}
      disabled={disabled}
    />
  );
}

function UserSelect({ value, onChange, onBlur, disabled }: SelectProps) {
  const [search, setSearch] = useDebouncedState("", 300);
  const { data: searchData, isFetching } = useUsers({ limit: 20, offset: 0, search: search || undefined });
  const { data: selectedUsers } = useUsersByIds(value);

  const searchIds = new Set((searchData?.items ?? []).map((u) => u.id));
  const options = [
    ...(searchData?.items ?? []),
    ...(selectedUsers ?? []).filter((u) => !searchIds.has(u.id)),
  ].map((u) => ({ value: u.id, label: u.username }));

  return (
    <Combobox
      multiple
      placeholder={disabled ? undefined : "Search users..."}
      options={options}
      filter={(option, text) => searchIds.has(option.value) || contains(option.label, text)}
      loading={isFetching}
      value={value}
      onValueChange={onChange}
      onInputValueChange={(text) => setSearch(text)}
      onBlur={onBlur}
      disabled={disabled}
    />
  );
}

export default function ClientAccessFields({ control }: { control: Control<ClientFormValues> }) {
  const restrict = useWatch({ control, name: "restrict_access" });
  const groups = useWatch({ control, name: "allowed_groups" });
  const users = useWatch({ control, name: "allowed_users" });
  const nobodyAllowed = !!restrict && !groups?.length && !users?.length;

  return (
    <Stack gap="md">
      <FormField
        control={control}
        name="restrict_access"
        label="Restrict Access"
        tooltip={accessTip.restrict_access}
        description="Only listed users and members of listed groups can sign in. With no users or groups listed, nobody can sign in."
      >
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

      {nobodyAllowed && (
        <Alert color="warning" title="Nobody can sign in to this client">
          Add allowed users or groups, or turn off Restrict Access.
        </Alert>
      )}

      <FormField control={control} name="allowed_groups" label="Allowed Groups" tooltip={accessTip.allowed_groups}>
        {(field) => (
          <GroupSelect value={field.value ?? []} onChange={field.onChange} onBlur={field.onBlur} disabled={!restrict} />
        )}
      </FormField>

      <FormField control={control} name="allowed_users" label="Allowed Users" tooltip={accessTip.allowed_users}>
        {(field) => (
          <UserSelect value={field.value ?? []} onChange={field.onChange} onBlur={field.onBlur} disabled={!restrict} />
        )}
      </FormField>

      {!restrict && (groups?.length || users?.length) ? (
        <Text textStyle="caption" muted>
          These lists are kept but not enforced while Restrict Access is off.
        </Text>
      ) : null}
    </Stack>
  );
}
