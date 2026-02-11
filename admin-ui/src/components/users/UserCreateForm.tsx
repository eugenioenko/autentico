import { Drawer, Form, Input, Select, Button, Space, message } from "antd";
import { useCreateUser } from "../../hooks/useUsers";
import type { UserCreateRequest } from "../../types/user";

interface UserCreateFormProps {
  open: boolean;
  onClose: () => void;
}

const ROLE_OPTIONS = [
  { label: "User", value: "user" },
  { label: "Admin", value: "admin" },
];

export default function UserCreateForm({
  open,
  onClose,
}: UserCreateFormProps) {
  const [form] = Form.useForm();
  const createUser = useCreateUser();

  const handleSubmit = async (values: UserCreateRequest) => {
    try {
      await createUser.mutateAsync(values);
      message.success("User created successfully");
      form.resetFields();
      onClose();
    } catch {
      message.error("Failed to create user");
    }
  };

  return (
    <Drawer
      title="Create User"
      open={open}
      onClose={onClose}
      width={480}
      extra={
        <Space>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={createUser.isPending}
          >
            Create
          </Button>
        </Space>
      }
    >
      <Form
        form={form}
        layout="vertical"
        onFinish={handleSubmit}
        initialValues={{ role: "user" }}
      >
        <Form.Item
          name="username"
          label="Username"
          rules={[{ required: true, message: "Username is required" }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="password"
          label="Password"
          rules={[
            { required: true, message: "Password is required" },
            { min: 6, message: "Password must be at least 6 characters" },
          ]}
        >
          <Input.Password />
        </Form.Item>

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
