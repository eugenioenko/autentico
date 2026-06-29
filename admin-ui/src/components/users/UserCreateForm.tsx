import { Drawer, Form, Input, Select, Button, Space, App } from "antd";
import { useCreateUser } from "../../hooks/useUsers";
import type { UserCreateRequest } from "../../types/user";
import { useTranslation } from "react-i18next";

interface UserCreateFormProps {
  open: boolean;
  onClose: () => void;
}

export default function UserCreateForm({
  open,
  onClose,
}: UserCreateFormProps) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const createUser = useCreateUser();

  const ROLE_OPTIONS = [
    { label: t("users.user"), value: "user" },
    { label: t("users.admin"), value: "admin" },
  ];

  const handleSubmit = async (values: UserCreateRequest) => {
    try {
      await createUser.mutateAsync(values);
      message.success(t("users.userCreated"));
      form.resetFields();
      onClose();
    } catch {
      message.error(t("users.createUserFailed"));
    }
  };

  return (
    <Drawer
      title={t("users.createUser")}
      open={open}
      onClose={onClose}
      width={480}
      extra={
        <Space>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={createUser.isPending}
          >
            {t("common.create")}
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
          label={t("users.username")}
          rules={[{ required: true, message: t("users.usernameRequired") }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="password"
          label={t("users.password")}
          rules={[
            { required: true, message: t("users.passwordRequired") },
            { min: 6, message: t("users.passwordMinLength") },
          ]}
        >
          <Input.Password />
        </Form.Item>

        <Form.Item
          name="email"
          label={t("users.email")}
          rules={[{ type: "email", message: t("users.mustBeValidEmail") }]}
        >
          <Input />
        </Form.Item>

        <Form.Item name="role" label={t("users.role")}>
          <Select options={ROLE_OPTIONS} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
