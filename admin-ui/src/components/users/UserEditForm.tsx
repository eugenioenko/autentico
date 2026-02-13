import { useEffect } from "react";
import { Drawer, Form, Input, Select, Button, Space, message } from "antd";
import { useUpdateUser } from "../../hooks/useUsers";
import type { UserResponseExt, UserUpdateRequest } from "../../types/user";

interface UserEditFormProps {
  open: boolean;
  user: UserResponseExt | null;
  onClose: () => void;
}

const ROLE_OPTIONS = [
  { label: "User", value: "user" },
  { label: "Admin", value: "admin" },
];

export default function UserEditForm({
  open,
  user,
  onClose,
}: UserEditFormProps) {
  const [form] = Form.useForm();
  const updateUser = useUpdateUser();

  useEffect(() => {
    if (user && open) {
      form.setFieldsValue({
        email: user.email,
        role: user.role,
      });
    }
  }, [user, open, form]);

  const handleSubmit = async (values: UserUpdateRequest) => {
    if (!user?.id) return;
    try {
      await updateUser.mutateAsync({ id: user.id, data: values });
      message.success("User updated successfully");
      onClose();
    } catch {
      message.error("Failed to update user");
    }
  };

  return (
    <Drawer
      title={`Edit User: ${user?.username ?? ""}`}
      open={open}
      onClose={onClose}
      width={480}
      extra={
        <Space>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={updateUser.isPending}
          >
            Save
          </Button>
        </Space>
      }
    >
      <Form form={form} layout="vertical" onFinish={handleSubmit}>
        <Form.Item
          name="email"
          label="Email"
          rules={[{ type: "email", message: "Must be a valid email" }]}
        >
          <Input />
        </Form.Item>

        <Form.Item name="role" label="Role">
          <Select options={ROLE_OPTIONS} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
