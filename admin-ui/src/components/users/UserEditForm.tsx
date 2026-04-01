import { useEffect } from "react";
import {
  Drawer,
  Form,
  Input,
  Select,
  Button,
  Space,
  message,
  Switch,
  Divider,
  Typography,
} from "antd";
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
        username: user.username,
        email: user.email,
        role: user.role,
        is_email_verified: user.is_email_verified,
        totp_verified: user.totp_verified,
        given_name: user.given_name,
        middle_name: user.middle_name,
        family_name: user.family_name,
        nickname: user.nickname,
        gender: user.gender,
        birthdate: user.birthdate,
        website: user.website,
        profile: user.profile,
        phone_number: user.phone_number,
        phone_number_verified: user.phone_number_verified,
        picture: user.picture,
        locale: user.locale,
        zoneinfo: user.zoneinfo,
        address_street: user.address_street,
        address_locality: user.address_locality,
        address_region: user.address_region,
        address_postal_code: user.address_postal_code,
        address_country: user.address_country,
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
          name="username"
          label="Username"
          rules={[{ required: true, message: "Username is required" }]}
        >
          <Input />
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

        <Form.Item
          name="password"
          label="New Password"
          extra="Leave empty to keep current password"
        >
          <Input.Password placeholder="Enter new password" autoComplete="new-password" />
        </Form.Item>

        <Divider />
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 16 }}>
          Profile
        </Typography.Text>

        <Form.Item name="given_name" label="First Name">
          <Input />
        </Form.Item>

        <Form.Item name="middle_name" label="Middle Name">
          <Input />
        </Form.Item>

        <Form.Item name="family_name" label="Last Name">
          <Input />
        </Form.Item>

        <Form.Item name="nickname" label="Nickname">
          <Input />
        </Form.Item>

        <Form.Item name="gender" label="Gender">
          <Input />
        </Form.Item>

        <Form.Item name="birthdate" label="Birthdate">
          <Input placeholder="YYYY-MM-DD" />
        </Form.Item>

        <Form.Item name="website" label="Website">
          <Input placeholder="https://..." />
        </Form.Item>

        <Form.Item name="phone_number" label="Phone Number">
          <Input />
        </Form.Item>

        <Form.Item
          name="phone_number_verified"
          label="Phone Verified"
          valuePropName="checked"
        >
          <Switch />
        </Form.Item>

        <Form.Item name="picture" label="Profile Picture URL">
          <Input placeholder="https://..." />
        </Form.Item>

        <Form.Item name="profile" label="Profile Page URL">
          <Input placeholder="https://..." />
        </Form.Item>

        <Form.Item name="locale" label="Locale">
          <Input placeholder="en-US" />
        </Form.Item>

        <Form.Item name="zoneinfo" label="Timezone">
          <Input placeholder="America/New_York" />
        </Form.Item>

        <Divider />
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 16 }}>
          Address
        </Typography.Text>

        <Form.Item name="address_street" label="Street">
          <Input />
        </Form.Item>

        <Form.Item name="address_locality" label="City">
          <Input />
        </Form.Item>

        <Form.Item name="address_region" label="State / Region">
          <Input />
        </Form.Item>

        <Form.Item name="address_postal_code" label="Postal Code">
          <Input />
        </Form.Item>

        <Form.Item name="address_country" label="Country">
          <Input />
        </Form.Item>

        <Divider />
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 16 }}>
          Status & Security
        </Typography.Text>

        <Form.Item
          name="is_email_verified"
          label="Email Verified"
          valuePropName="checked"
        >
          <Switch />
        </Form.Item>

        <Form.Item
          name="totp_verified"
          label="MFA Enrolled"
          valuePropName="checked"
          extra="Turning this off will reset the user's MFA setup."
        >
          <Switch />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
