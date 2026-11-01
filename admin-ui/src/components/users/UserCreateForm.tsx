import { useId } from "react";
import { useForm } from "react-hook-form";
import { Button, Drawer, Input, Select, Stack, toast } from "@yarcl/react";
import { useCreateUser } from "../../hooks/useUsers";
import type { UserCreateRequest } from "../../types/user";
import { FormField } from "../FormField";
import PasswordInput from "../PasswordInput";
import { emailRule } from "../../lib/validation";

interface UserCreateFormProps {
  open: boolean;
  onClose: () => void;
}

const ROLE_OPTIONS = [
  { label: "User", value: "user" },
  { label: "Admin", value: "admin" },
];

const EMPTY: UserCreateRequest = { username: "", password: "", email: "", role: "user" };

export default function UserCreateForm({ open, onClose }: UserCreateFormProps) {
  const formId = useId();
  const { control, handleSubmit, reset } = useForm<UserCreateRequest>({ defaultValues: EMPTY });
  const createUser = useCreateUser();

  const onSubmit = async (values: UserCreateRequest) => {
    try {
      await createUser.mutateAsync(values);
      toast({ title: "User created successfully", color: "success" });
      reset(EMPTY);
      onClose();
    } catch {
      toast({ title: "Failed to create user", color: "danger" });
    }
  };

  return (
    <Drawer
      title="Create User"
      open={open}
      onOpenChange={(next) => !next && onClose()}
      side="right"
      size="md"
      footer={
        <>
          <Button variant="ghost" color="neutral" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form={formId} loading={createUser.isPending}>
            Create
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit(onSubmit)} noValidate>
        <Stack gap="md">
          <FormField control={control} name="username" label="Username" rules={{ required: "Username is required" }}>
            {(field) => <Input {...field} autoComplete="off" />}
          </FormField>

          <FormField
            control={control}
            name="password"
            label="Password"
            rules={{
              required: "Password is required",
              minLength: { value: 6, message: "Password must be at least 6 characters" },
            }}
          >
            {(field) => <PasswordInput {...field} />}
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
        </Stack>
      </form>
    </Drawer>
  );
}
