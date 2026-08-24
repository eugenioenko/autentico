import { useEffect } from "react";
import { Drawer, Form, Input, InputNumber, Switch, Alert, Space, Button, Typography, App } from "antd";
import { useUpdateFederationProvider } from "../../hooks/useFederation";
import type { FederationProvider, FederationProviderUpdateRequest } from "../../types/federation";
import { useTranslation } from "react-i18next";

interface Props {
  open: boolean;
  provider: FederationProvider | null;
  onClose: () => void;
}

export default function FederationEditForm({ open, provider, onClose }: Props) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const updateProvider = useUpdateFederationProvider();

  useEffect(() => {
    if (provider) {
      form.setFieldsValue({
        name: provider.name,
        issuer: provider.issuer,
        client_id: provider.client_id,
        icon_svg: provider.icon_svg,
        enabled: provider.enabled,
        sort_order: provider.sort_order,
      });
    }
  }, [provider, form]);

  const handleSubmit = async (values: FederationProviderUpdateRequest) => {
    if (!provider) return;
    try {
      await updateProvider.mutateAsync({ id: provider.id, data: values });
      message.success(t("federation.providerUpdated"));
      onClose();
    } catch {
      message.error(t("federation.updateProviderFailed"));
    }
  };

  const callbackURL = provider
    ? `${window.location.origin}/oauth2/federation/${provider.id}/callback`
    : "";

  return (
    <Drawer
      title={t("federation.editFederationProvider")}
      open={open}
      onClose={onClose}
      width={520}
      extra={
        <Space>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={updateProvider.isPending}
          >
            {t("common.save")}
          </Button>
        </Space>
      }
    >
      {provider && (
        <Alert
          type="info"
          style={{ marginBottom: 20 }}
          message={t("federation.redirectUriForProvider")}
          description={
            <Space direction="vertical" size={4}>
              <Typography.Text>
                {t("federation.redirectUriDesc")}
              </Typography.Text>
              <Typography.Text code copyable>
                {callbackURL}
              </Typography.Text>
            </Space>
          }
        />
      )}

      <Form form={form} layout="vertical" onFinish={handleSubmit}>
        <Form.Item
          name="name"
          label={t("federation.displayName")}
          rules={[{ required: true, message: t("federation.nameRequired") }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="issuer"
          label={t("federation.issuerUrl")}
          rules={[
            { required: true, message: t("federation.issuerRequired") },
            { type: "url", message: t("federation.mustBeValidUrl") },
          ]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="client_id"
          label={t("federation.clientIdLabel")}
          rules={[{ required: true, message: t("federation.clientIdRequired") }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="client_secret"
          label={t("federation.clientSecretLabel")}
          extra={t("federation.leaveEmptyToKeepSecret")}
        >
          <Input.Password placeholder={t("federation.leaveEmptyToKeepCurrent")} />
        </Form.Item>

        <Form.Item name="icon_svg" label={t("federation.iconSvg")}>
          <Input.TextArea rows={3} />
        </Form.Item>

        <Form.Item name="sort_order" label={t("federation.sortOrder")} extra={t("federation.sortOrderExtra")}>
          <InputNumber min={0} style={{ width: "100%" }} />
        </Form.Item>

        <Form.Item name="enabled" label={t("common.enabled")} valuePropName="checked">
          <Switch />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
