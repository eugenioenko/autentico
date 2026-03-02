import { useState } from "react";
import { Drawer, Form, Input, InputNumber, Switch, Alert, Space, Button, message, Typography } from "antd";
import { InfoCircleOutlined } from "@ant-design/icons";
import { useCreateFederationProvider } from "../../hooks/useFederation";
import type { FederationProviderCreateRequest } from "../../types/federation";

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function FederationCreateForm({ open, onClose }: Props) {
  const [form] = Form.useForm();
  const createProvider = useCreateFederationProvider();
  const [slug, setSlug] = useState("");

  const handleSubmit = async (values: FederationProviderCreateRequest) => {
    try {
      await createProvider.mutateAsync(values);
      message.success("Federation provider created");
      form.resetFields();
      setSlug("");
      onClose();
    } catch {
      message.error("Failed to create federation provider");
    }
  };

  return (
    <Drawer
      title="Add Federation Provider"
      open={open}
      onClose={onClose}
      width={520}
      extra={
        <Space>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={createProvider.isPending}
          >
            Create
          </Button>
        </Space>
      }
    >
      <Alert
        type="info"
        icon={<InfoCircleOutlined />}
        showIcon
        style={{ marginBottom: 20 }}
        message="How to set up a provider"
        description={
          <Space direction="vertical" size={4}>
            <Typography.Text>
              Set a <strong>Provider ID</strong> below, register this redirect URI in your provider's console, then paste the credentials here.
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
          label="Provider ID"
          extra="URL-safe slug used in the redirect URI. Cannot be changed after creation."
          rules={[
            { required: true, message: "Provider ID is required" },
            { pattern: /^[a-z0-9-]+$/, message: "Only lowercase letters, numbers, and hyphens" },
          ]}
        >
          <Input
            placeholder="e.g. google, microsoft, okta"
            autoComplete="federation-provider-id"
            onChange={(e) => setSlug(e.target.value.trim())}
          />
        </Form.Item>

        <Form.Item
          name="name"
          label="Display Name"
          rules={[{ required: true, message: "Name is required" }]}
        >
          <Input placeholder="Google" />
        </Form.Item>

        <Form.Item
          name="issuer"
          label="Issuer URL"
          extra="The OIDC discovery base URL (without /.well-known/openid-configuration)"
          rules={[
            { required: true, message: "Issuer is required" },
            { type: "url", message: "Must be a valid URL" },
          ]}
        >
          <Input placeholder="https://accounts.google.com" />
        </Form.Item>

        <Form.Item
          name="client_id"
          label="Client ID"
          rules={[{ required: true, message: "Client ID is required" }]}
        >
          <Input placeholder="123456789-abc.apps.googleusercontent.com" autoComplete="federation-client-id" />
        </Form.Item>

        <Form.Item
          name="client_secret"
          label="Client Secret"
          rules={[{ required: true, message: "Client secret is required" }]}
        >
          <Input.Password placeholder="Client secret from your provider" autoComplete="new-password" />
        </Form.Item>

        <Form.Item name="icon_svg" label="Icon SVG" extra="Paste SVG markup for the provider button icon (optional).">
          <Input.TextArea rows={3} placeholder='<svg xmlns="http://www.w3.org/2000/svg" ...>...</svg>' />
        </Form.Item>

        <Form.Item name="sort_order" label="Sort Order" extra="Lower numbers appear first on the login page.">
          <InputNumber min={0} style={{ width: "100%" }} />
        </Form.Item>

        <Form.Item name="enabled" label="Enabled" valuePropName="checked">
          <Switch />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
