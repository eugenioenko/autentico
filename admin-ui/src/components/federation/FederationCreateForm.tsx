import { useState } from "react";
import { Drawer, Form, Input, InputNumber, Switch, Alert, Space, Button, Typography, App } from "antd";
import { InfoCircleOutlined } from "@ant-design/icons";
import { useCreateFederationProvider } from "../../hooks/useFederation";
import type { FederationProviderCreateRequest } from "../../types/federation";
import { useTranslation, Trans } from "react-i18next";

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function FederationCreateForm({ open, onClose }: Props) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const createProvider = useCreateFederationProvider();
  const [slug, setSlug] = useState("");

  const handleSubmit = async (values: FederationProviderCreateRequest) => {
    try {
      await createProvider.mutateAsync(values);
      message.success(t("federation.providerCreated"));
      form.resetFields();
      setSlug("");
      onClose();
    } catch {
      message.error(t("federation.createProviderFailed"));
    }
  };

  return (
    <Drawer
      title={t("federation.addFederationProvider")}
      open={open}
      onClose={onClose}
      width={520}
      extra={
        <Space>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={createProvider.isPending}
          >
            {t("common.create")}
          </Button>
        </Space>
      }
      >
      <Alert
        type="info"
        icon={<InfoCircleOutlined />}
        showIcon
        style={{ marginBottom: 20 }}
        message={t("federation.howToSetup")}
        description={
          <Space direction="vertical" size={4}>
            <Typography.Text>
              <Trans i18nKey="federation.howToSetupDesc">
                Set the <strong>Provider ID</strong> below, register this redirect URI in the provider's developer console, then paste the credentials here.
              </Trans>
            </Typography.Text>
            <Typography.Text code copyable={!!slug}>
              {slug
                ? `${window.location.origin}/oauth2/federation/${slug}/callback`
                : `${window.location.origin}/oauth2/federation/{id}/callback`}
            </Typography.Text>
          </Space>
        }
      />

      <Form
        form={form}
        layout="vertical"
        onFinish={handleSubmit}
        initialValues={{ enabled: true, sort_order: 0 }}
      >
        <Form.Item
          name="id"
          label={t("federation.providerId")}
          extra={t("federation.providerIdExtra")}
          rules={[
            { required: true, message: t("federation.providerIdRequired") },
            { pattern: /^[a-z0-9-]+$/, message: t("federation.providerIdPattern") },
          ]}
        >
          <Input
            placeholder={t("federation.providerIdPlaceholder")}
            autoComplete="federation-provider-id"
            onChange={(e) => setSlug(e.target.value.trim())}
          />
        </Form.Item>

        <Form.Item
          name="name"
          label={t("federation.displayName")}
          rules={[{ required: true, message: t("federation.nameRequired") }]}
        >
          <Input placeholder={t("federation.namePlaceholder")} />
        </Form.Item>

        <Form.Item
          name="issuer"
          label={t("federation.issuerUrl")}
          extra={t("federation.issuerUrlExtra")}
          rules={[
            { required: true, message: t("federation.issuerRequired") },
            { type: "url", message: t("federation.mustBeValidUrl") },
          ]}
        >
          <Input placeholder={t("federation.issuerPlaceholder")} />
        </Form.Item>

        <Form.Item
          name="client_id"
          label={t("federation.clientIdLabel")}
          rules={[{ required: true, message: t("federation.clientIdRequired") }]}
        >
          <Input placeholder={t("federation.clientIdPlaceholder")} autoComplete="federation-client-id" />
        </Form.Item>

        <Form.Item
          name="client_secret"
          label={t("federation.clientSecretLabel")}
          rules={[{ required: true, message: t("federation.clientSecretRequired") }]}
        >
          <Input.Password placeholder={t("federation.clientSecretPlaceholder")} autoComplete="new-password" />
        </Form.Item>

        <Form.Item name="icon_svg" label={t("federation.iconSvg")} extra={t("federation.iconSvgExtra")}>
          <Input.TextArea rows={3} placeholder='<svg xmlns="http://www.w3.org/2000/svg" ...>...</svg>' />
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
