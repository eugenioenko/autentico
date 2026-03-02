import { useEffect } from "react";
import {
  Drawer,
  Form,
  Input,
  Select,
  Button,
  Space,
  message,
  Divider,
  Collapse,
  Switch,
} from "antd";
import { PlusOutlined, MinusCircleOutlined } from "@ant-design/icons";
import { useUpdateClient } from "../../hooks/useClients";
import type {
  ClientInfoResponse,
  ClientUpdateRequest,
} from "../../types/client";

interface ClientEditFormProps {
  open: boolean;
  client: ClientInfoResponse | null;
  onClose: () => void;
}

const GRANT_TYPE_OPTIONS = [
  { label: "Authorization Code", value: "authorization_code" },
  { label: "Refresh Token", value: "refresh_token" },
  { label: "Client Credentials", value: "client_credentials" },
  { label: "Password", value: "password" },
];

const RESPONSE_TYPE_OPTIONS = [
  { label: "Code", value: "code" },
  { label: "Token", value: "token" },
  { label: "ID Token", value: "id_token" },
];

const AUTH_METHOD_OPTIONS = [
  { label: "Client Secret Basic", value: "client_secret_basic" },
  { label: "Client Secret Post", value: "client_secret_post" },
  { label: "None", value: "none" },
];

const SCOPE_OPTIONS = [
  { label: "openid", value: "openid" },
  { label: "profile", value: "profile" },
  { label: "email", value: "email" },
  { label: "address", value: "address" },
  { label: "phone", value: "phone" },
  { label: "offline_access", value: "offline_access" },
];

export default function ClientEditForm({
  open,
  client,
  onClose,
}: ClientEditFormProps) {
  const [form] = Form.useForm();
  const updateClient = useUpdateClient();

  useEffect(() => {
    if (client && open) {
      form.setFieldsValue({
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        response_types: client.response_types,
        scopes: client.scopes?.split(" ").filter(Boolean) ?? [],
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        access_token_expiration: client.access_token_expiration,
        refresh_token_expiration: client.refresh_token_expiration,
        authorization_code_expiration: client.authorization_code_expiration,
        allowed_audiences: client.allowed_audiences,
        allow_self_signup: client.allow_self_signup,
        sso_session_idle_timeout: client.sso_session_idle_timeout,
        trust_device_enabled: client.trust_device_enabled,
        trust_device_expiration: client.trust_device_expiration,
      });
    }
  }, [client, open, form]);

  const handleSubmit = async (
    values: Omit<ClientUpdateRequest, "scopes"> & { scopes?: string[] },
  ) => {
    if (!client?.client_id) return;
    try {
      await updateClient.mutateAsync({
        clientId: client.client_id,
        data: { ...values, scopes: values.scopes?.join(" ") },
      });
      message.success("Client updated successfully");
      onClose();
    } catch {
      message.error("Failed to update client");
    }
  };

  return (
    <Drawer
      title={`Edit Client: ${client?.client_name ?? ""}`}
      open={open}
      onClose={onClose}
      width={520}
      extra={
        <Space>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={updateClient.isPending}
          >
            Save
          </Button>
        </Space>
      }
    >
      <Form form={form} layout="vertical" onFinish={handleSubmit}>
        <Form.Item
          name="client_name"
          label="Client Name"
          rules={[{ required: true, message: "Client name is required" }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          label="Client ID"
          extra="Client ID cannot be changed after creation."
        >
          <Input value={client?.client_id} disabled />
        </Form.Item>

        <Form.List name="redirect_uris">
          {(fields, { add, remove }, { errors }) => (
            <>
              {fields.map((field) => (
                <Form.Item
                  key={field.key}
                  label={field.name === 0 ? "Redirect URIs" : undefined}
                  required={field.name === 0}
                >
                  <Space.Compact style={{ width: "100%" }}>
                    <Form.Item
                      {...field}
                      noStyle
                      rules={[
                        { required: true, message: "URI is required" },
                        { type: "url", message: "Must be a valid URL" },
                      ]}
                    >
                      <Input style={{ width: "100%" }} />
                    </Form.Item>
                    {fields.length > 1 && (
                      <Button
                        icon={<MinusCircleOutlined />}
                        onClick={() => remove(field.name)}
                      />
                    )}
                  </Space.Compact>
                </Form.Item>
              ))}
              <Form.Item>
                <Button
                  type="dashed"
                  onClick={() => add()}
                  block
                  icon={<PlusOutlined />}
                >
                  Add Redirect URI
                </Button>
                <Form.ErrorList errors={errors} />
              </Form.Item>
            </>
          )}
        </Form.List>

        <Form.Item name="grant_types" label="Grant Types">
          <Select mode="multiple" options={GRANT_TYPE_OPTIONS} />
        </Form.Item>

        <Form.Item name="response_types" label="Response Types">
          <Select mode="multiple" options={RESPONSE_TYPE_OPTIONS} />
        </Form.Item>

        <Form.Item
          name="scopes"
          label="Scopes"
          extra="Select standard OIDC scopes or type to add custom ones."
        >
          <Select
            mode="tags"
            options={SCOPE_OPTIONS}
            placeholder="Select or type scopes..."
          />
        </Form.Item>

        <Form.Item
          name="token_endpoint_auth_method"
          label="Token Endpoint Auth Method"
        >
          <Select options={AUTH_METHOD_OPTIONS} />
        </Form.Item>

        <Divider />

        <Collapse
          ghost
          items={[
            {
              key: "overrides",
              label: "Configuration Overrides (Optional)",
              children: (
                <Space direction="vertical" style={{ width: "100%" }}>
                  <Form.Item
                    label="Access Token Expiration"
                    name="access_token_expiration"
                    extra="Example: 15m, 1h. Leave empty to use global default."
                  >
                    <Input placeholder="Global default" />
                  </Form.Item>

                  <Form.Item
                    label="Refresh Token Expiration"
                    name="refresh_token_expiration"
                    extra="Example: 720h. Leave empty to use global default."
                  >
                    <Input placeholder="Global default" />
                  </Form.Item>

                  <Form.Item
                    label="Auth Code Expiration"
                    name="authorization_code_expiration"
                  >
                    <Input placeholder="Global default (e.g. 10m)" />
                  </Form.Item>

                  <Form.Item
                    label="Allowed Audiences"
                    name="allowed_audiences"
                    extra="Specific audiences for tokens issued to this client."
                  >
                    <Select mode="tags" placeholder="Add audiences..." />
                  </Form.Item>

                  <Form.Item
                    label="Allow Self Signup"
                    name="allow_self_signup"
                    valuePropName="checked"
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="SSO Session Idle Timeout"
                    name="sso_session_idle_timeout"
                  >
                    <Input placeholder="Global default (e.g. 30m)" />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Enabled"
                    name="trust_device_enabled"
                    valuePropName="checked"
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label="Trust Device Expiration"
                    name="trust_device_expiration"
                  >
                    <Input placeholder="Global default (e.g. 720h)" />
                  </Form.Item>
                </Space>
              ),
            },
          ]}
        />
      </Form>
    </Drawer>
  );
}
