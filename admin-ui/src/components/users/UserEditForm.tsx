import { useEffect, useId } from "react";
import { useForm } from "react-hook-form";
import { Button, Divider, Drawer, Input, Select, Stack, Switch, Text, toast } from "@yarcl/react";
import { useUpdateUser } from "../../hooks/useUsers";
import type { UserResponseExt, UserUpdateRequest } from "../../types/user";
import { FormField } from "../FormField";
import PasswordInput from "../PasswordInput";
import { emailRule } from "../../lib/validation";

interface UserEditFormProps {
  open: boolean;
  user: UserResponseExt | null;
  onClose: () => void;
}

const ROLE_OPTIONS = [
  { label: "User", value: "user" },
  { label: "Admin", value: "admin" },
];

type Values = Required<UserUpdateRequest>;

type TextFieldName = {
  [K in keyof Values]: Values[K] extends string ? K : never;
}[keyof Values];

interface TextFieldDef {
  name: TextFieldName;
  label: string;
  placeholder?: string;
}

const PROFILE_FIELDS: TextFieldDef[] = [
  { name: "given_name", label: "First Name" },
  { name: "middle_name", label: "Middle Name" },
  { name: "family_name", label: "Last Name" },
  { name: "nickname", label: "Nickname" },
  { name: "gender", label: "Gender" },
  { name: "birthdate", label: "Birthdate", placeholder: "YYYY-MM-DD" },
  { name: "website", label: "Website", placeholder: "https://..." },
  { name: "phone_number", label: "Phone Number" },
];

const PROFILE_URL_FIELDS: TextFieldDef[] = [
  { name: "picture", label: "Profile Picture URL", placeholder: "https://..." },
  { name: "profile", label: "Profile Page URL", placeholder: "https://..." },
  { name: "locale", label: "Locale", placeholder: "en-US" },
  { name: "zoneinfo", label: "Timezone", placeholder: "America/New_York" },
];

const ADDRESS_FIELDS: TextFieldDef[] = [
  { name: "address_street", label: "Street" },
  { name: "address_locality", label: "City" },
  { name: "address_region", label: "State / Region" },
  { name: "address_postal_code", label: "Postal Code" },
  { name: "address_country", label: "Country" },
];

const EMPTY: Values = {
  username: "",
  password: "",
  email: "",
  role: "user",
  is_email_verified: false,
  totp_verified: false,
  given_name: "",
  middle_name: "",
  family_name: "",
  nickname: "",
  gender: "",
  birthdate: "",
  website: "",
  profile: "",
  phone_number: "",
  phone_number_verified: false,
  picture: "",
  locale: "",
  zoneinfo: "",
  address_street: "",
  address_locality: "",
  address_region: "",
  address_postal_code: "",
  address_country: "",
};

function toValues(user: UserResponseExt): Values {
  const values = { ...EMPTY };
  for (const key of Object.keys(EMPTY) as (keyof Values)[]) {
    if (key === "password") continue;
    const value = user[key as keyof UserResponseExt];
    if (value !== undefined && value !== null) (values as Record<string, unknown>)[key] = value;
  }
  return values;
}

export default function UserEditForm({ open, user, onClose }: UserEditFormProps) {
  const formId = useId();
  const { control, handleSubmit, reset } = useForm<Values>({ defaultValues: EMPTY });
  const updateUser = useUpdateUser();

  useEffect(() => {
    if (user && open) reset(toValues(user));
  }, [user, open, reset]);

  const onSubmit = async (values: Values) => {
    if (!user?.id) return;
    try {
      await updateUser.mutateAsync({ id: user.id, data: values });
      toast({ title: "User updated successfully", color: "success" });
      onClose();
    } catch {
      toast({ title: "Failed to update user", color: "danger" });
    }
  };

  const textFields = (fields: TextFieldDef[]) =>
    fields.map(({ name, label, placeholder }) => (
      <FormField key={name} control={control} name={name} label={label}>
        {(field) => <Input {...field} value={field.value ?? ""} placeholder={placeholder} />}
      </FormField>
    ));

  return (
    <Drawer
      title={`Edit User: ${user?.username ?? ""}`}
      open={open}
      onOpenChange={(next) => !next && onClose()}
      side="right"
      size="md"
      footer={
        <>
          <Button variant="ghost" color="neutral" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form={formId} loading={updateUser.isPending}>
            Save
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit(onSubmit)} noValidate>
        <Stack gap="md">
          <FormField control={control} name="username" label="Username" rules={{ required: "Username is required" }}>
            {(field) => <Input {...field} />}
          </FormField>

          <FormField control={control} name="email" label="Email" rules={{ pattern: emailRule() }}>
            {(field) => <Input {...field} type="email" value={field.value ?? ""} />}
          </FormField>

          <FormField control={control} name="role" label="Role">
            {(field) => (
              <Select
                options={ROLE_OPTIONS}
                value={field.value ?? null}
                onValueChange={(v) => field.onChange(v ?? "user")}
                onBlur={field.onBlur}
              />
            )}
          </FormField>

          <FormField control={control} name="password" label="New Password" description="Leave empty to keep current password">
            {(field) => <PasswordInput {...field} value={field.value ?? ""} placeholder="Enter new password" />}
          </FormField>

          <Divider />
          <Text muted>Profile</Text>

          {textFields(PROFILE_FIELDS)}

          <FormField control={control} name="phone_number_verified" label="Phone Verified">
            {(field) => (
              <Switch
                name={field.name}
                ref={field.ref}
                onBlur={field.onBlur}
                checked={!!field.value}
                onChange={(e) => field.onChange(e.target.checked)}
              />
            )}
          </FormField>

          {textFields(PROFILE_URL_FIELDS)}

          <Divider />
          <Text muted>Address</Text>

          {textFields(ADDRESS_FIELDS)}

          <Divider />
          <Text muted>Status & Security</Text>

          <FormField control={control} name="is_email_verified" label="Email Verified">
            {(field) => (
              <Switch
                name={field.name}
                ref={field.ref}
                onBlur={field.onBlur}
                checked={!!field.value}
                onChange={(e) => field.onChange(e.target.checked)}
              />
            )}
          </FormField>

          <FormField
            control={control}
            name="totp_verified"
            label="MFA Enrolled"
            description="Turning this off will reset the user's MFA setup."
          >
            {(field) => (
              <Switch
                name={field.name}
                ref={field.ref}
                onBlur={field.onBlur}
                checked={!!field.value}
                onChange={(e) => field.onChange(e.target.checked)}
              />
            )}
          </FormField>
        </Stack>
      </form>
    </Drawer>
  );
}
