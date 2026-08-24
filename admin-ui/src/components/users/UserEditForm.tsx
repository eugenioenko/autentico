import { useEffect } from "react";
import {
  Drawer,
  Form,
  Input,
  Select,
  Button,
  Space,
  Switch,
  Divider,
  Typography,
  App,
} from "antd";
import { useUpdateUser } from "../../hooks/useUsers";
import type { UserResponseExt, UserUpdateRequest } from "../../types/user";
import { useTranslation } from "react-i18next";

interface UserEditFormProps {
  open: boolean;
  user: UserResponseExt | null;
  onClose: () => void;
}

export default function UserEditForm({
  open,
  user,
  onClose,
}: UserEditFormProps) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const updateUser = useUpdateUser();

  const ROLE_OPTIONS = [
    { label: t("users.user"), value: "user" },
    { label: t("users.admin"), value: "admin" },
  ];

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
      message.success(t("users.userUpdated"));
      onClose();
    } catch {
      message.error(t("users.updateUserFailed"));
    }
  };

  return (
    <Drawer
      title={`${t("users.editUser")}: ${user?.username ?? ""}`}
      open={open}
      onClose={onClose}
      width={480}
      extra={
        <Space>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={updateUser.isPending}
          >
            {t("common.save")}
          </Button>
        </Space>
      }
    >
      <Form form={form} layout="vertical" onFinish={handleSubmit}>
        <Form.Item
          name="username"
          label={t("users.username")}
          rules={[{ required: true, message: t("users.usernameRequired") }]}
        >
          <Input />
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

        <Form.Item
          name="password"
          label={t("users.newPassword")}
          extra={t("users.leaveEmptyKeepCurrent")}
        >
          <Input.Password placeholder={t("users.enterNewPassword")} autoComplete="new-password" />
        </Form.Item>

        <Divider />
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 16 }}>
          {t("common.profile")}
        </Typography.Text>

        <Form.Item name="given_name" label={t("settings.givenName")}>
          <Input />
        </Form.Item>

        <Form.Item name="middle_name" label={t("settings.middleName")}>
          <Input />
        </Form.Item>

        <Form.Item name="family_name" label={t("settings.familyName")}>
          <Input />
        </Form.Item>

        <Form.Item name="nickname" label={t("settings.nickname")}>
          <Input />
        </Form.Item>

        <Form.Item name="gender" label={t("settings.gender")}>
          <Input />
        </Form.Item>

        <Form.Item name="birthdate" label={t("settings.birthdate")}>
          <Input placeholder="YYYY-MM-DD" />
        </Form.Item>

        <Form.Item name="website" label={t("settings.website")}>
          <Input placeholder="https://..." />
        </Form.Item>

        <Form.Item name="phone_number" label={t("settings.phoneNumber")}>
          <Input />
        </Form.Item>

        <Form.Item
          name="phone_number_verified"
          label={t("users.phoneVerified")}
          valuePropName="checked"
        >
          <Switch />
        </Form.Item>

        <Form.Item name="picture" label={t("settings.picture")}>
          <Input placeholder="https://..." />
        </Form.Item>

        <Form.Item name="profile" label={t("settings.profileUrl")}>
          <Input placeholder="https://..." />
        </Form.Item>

        <Form.Item name="locale" label={t("settings.locale")}>
          <Input placeholder="en-US" />
        </Form.Item>

        <Form.Item name="zoneinfo" label="Timezone">
          <Input placeholder="America/New_York" />
        </Form.Item>

        <Divider />
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 16 }}>
          {t("common.address")}
        </Typography.Text>

        <Form.Item name="address_street" label="Street">
          <Input />
        </Form.Item>

        <Form.Item name="address_locality" label="City">
          <Input />
        </Form.Item>

        <Form.Item name="address_region" label="State/Region">
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
          {t("common.statusAndSecurity")}
        </Typography.Text>

        <Form.Item
          name="is_email_verified"
          label={t("users.emailVerified")}
          valuePropName="checked"
        >
          <Switch />
        </Form.Item>

        <Form.Item
          name="totp_verified"
          label={t("users.mfaEnrolled")}
          valuePropName="checked"
          extra={t("users.disablingResetsMfa")}
        >
          <Switch />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
