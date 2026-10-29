import { useEffect, useState } from "react";
import { Drawer, Form, Input, InputNumber, Switch, Alert, Space, Button, Typography, App } from "antd";
import { useUpdateFederationProvider } from "../../hooks/useFederation";
import type { FederationProvider, FederationProviderUpdateRequest } from "../../types/federation";
import ClaimRequirementsEditor from './ClaimRequirementsEditor';
import { validateClaimRequirements } from '../../api/federation';

interface Props {
  open: boolean;
  provider: FederationProvider | null;
  onClose: () => void;
}

export default function FederationEditForm({ open, provider, onClose }: Props) {
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const updateProvider = useUpdateFederationProvider();
  const [rulesTouched, setRulesTouched] = useState(false);

  useEffect(() => {
    if (provider) {
      setRulesTouched(false);
      form.setFieldsValue({
        claim_requirements: provider.claim_requirements ?? [],
        name: provider.name,
        issuer: provider.issuer,
        client_id: provider.client_id,
        client_secret: "",
        icon_svg: provider.icon_svg,
        enabled: provider.enabled,
        sort_order: provider.sort_order,
      });
    }
  }, [provider, form]);

  const handleSubmit = async (values: FederationProviderUpdateRequest) => {
    if (!provider) return;
    if (provider.claim_requirements_error && !rulesTouched) delete values.claim_requirements;
    try {
      await updateProvider.mutateAsync({ id: provider.id, data: values });
      message.success("Federation provider updated");
      onClose();
    } catch {
      message.error("Failed to update federation provider");
    }
  };

  const callbackURL = provider
    ? `${window.location.origin}/oauth2/federation/${provider.id}/callback`
    : "";

  return (
    <Drawer
      title="Edit Federation Provider"
      open={open}
      onClose={onClose}
      width={760}
      extra={
        <Space>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={updateProvider.isPending}
          >
            Save
          </Button>
        </Space>
      }
    >
      {provider && (
        <Alert
          type="info"
          style={{ marginBottom: 20 }}
          message="Redirect URI for this provider"
          description={
            <Space direction="vertical" size={4}>
              <Typography.Text>
                Register this redirect URI in your identity provider's developer console:
              </Typography.Text>
              <Typography.Text code copyable>
                {callbackURL}
              </Typography.Text>
            </Space>
          }
        />
      )}

      {provider?.claim_requirements_error && <Alert type="error" title="Stored claim requirements are invalid" description="Login is blocked. Replace the requirements or explicitly clear them to repair this provider. Other edits preserve the invalid policy." />}
      <Form form={form} layout="vertical" onFinish={handleSubmit} onValuesChange={changed => { if ('claim_requirements' in changed) setRulesTouched(true); }}>
        <Form.Item
          name="name"
          label="Display Name"
          rules={[{ required: true, message: "Name is required" }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="issuer"
          label="Issuer URL"
          rules={[
            { required: true, message: "Issuer is required" },
            { type: "url", message: "Must be a valid URL" },
          ]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="client_id"
          label="Client ID"
          rules={[{ required: true, message: "Client ID is required" }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="client_secret"
          label="Client Secret"
          extra="Leave empty to keep the existing secret."
        >
          <Input.Password placeholder="Leave empty to keep unchanged" />
        </Form.Item>

        <Form.Item name="icon_svg" label="Icon SVG">
          <Input.TextArea rows={3} />
        </Form.Item>

        <Form.Item name="claim_requirements" label="Claim requirements" validateTrigger={[]} rules={[{ validator: validateClaimRequirements }]}>
          <ClaimRequirementsEditor />
        </Form.Item>
        {provider?.claim_requirements_error && <Button onClick={() => { form.setFieldValue('claim_requirements', []); setRulesTouched(true); }}>Clear invalid requirements</Button>}

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
