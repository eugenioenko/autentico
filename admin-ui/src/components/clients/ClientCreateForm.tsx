import { useState } from "react";
import {
  Drawer,
  Form,
  Input,
  Select,
  Button,
  Space,
  Modal,
  Typography,
  Alert,
  Divider,
  Collapse,
  Switch,
  App,
} from "antd";
import {
  PlusOutlined,
  MinusCircleOutlined,
  CopyOutlined,
  ExclamationCircleOutlined,
} from "@ant-design/icons";
import { useCreateClient } from "../../hooks/useClients";
import type { ClientCreateRequest, ClientResponse } from "../../types/client";
import { tip, overrideTip } from "./clientTips";

interface ClientCreateFormProps {
  open: boolean;
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

const CLIENT_TYPE_OPTIONS = [
  { label: "Confidential", value: "confidential" },
  { label: "Public", value: "public" },
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

export default function ClientCreateForm({
  open,
  onClose,
}: ClientCreateFormProps) {
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const createClient = useCreateClient();
  const [secretModal, setSecretModal] = useState<ClientResponse | null>(null);

  const handleSubmit = async (
    values: Omit<ClientCreateRequest, "scopes"> & { scopes?: string[] },
  ) => {
    try {
      const result = await createClient.mutateAsync({
        ...values,
        scopes: values.scopes?.join(" "),
      });
      form.resetFields();
      onClose();
      if (result.client_secret) {
        setSecretModal(result);
      } else {
        message.success("Client created successfully");
      }
    } catch {
      message.error("Failed to create client");
    }
  };

  const handleCopySecret = () => {
    if (secretModal?.client_secret) {
      navigator.clipboard.writeText(secretModal.client_secret);
      message.success("Secret copied to clipboard");
    }
  };

  return (
    <>
      <Drawer
        title="Create Client"
        open={open}
        onClose={onClose}
        width={520}
        extra={
          <Space>
            <Button onClick={onClose}>Cancel</Button>
            <Button
              type="primary"
              onClick={() => form.submit()}
              loading={createClient.isPending}
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
          initialValues={{
            client_type: "public",
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            token_endpoint_auth_method: "client_secret_basic",
            scopes: ["openid", "profile", "email", "offline_access"],
            redirect_uris: [""],
            post_logout_redirect_uris: [],
          }}
        >
          <Form.Item
            name="client_name"
            label="Client Name"
            rules={[{ required: true, message: "Client name is required" }]}
            tooltip={{ title: tip("client_name"), icon: <ExclamationCircleOutlined /> }}
          >
            <Input placeholder="My Application" />
          </Form.Item>

          <Form.Item
            name="client_id"
            label="Client ID"
            tooltip={{ title: tip("client_id"), icon: <ExclamationCircleOutlined /> }}
          >
            <Input placeholder="my-custom-client-id" autoComplete="off" />
          </Form.Item>

          <Form.Item
            name="client_type"
            label="Client Type"
            tooltip={{ title: tip("client_type"), icon: <ExclamationCircleOutlined /> }}
          >
            <Select options={CLIENT_TYPE_OPTIONS} />
          </Form.Item>

          <Form.Item noStyle dependencies={["client_type"]}>
            {() =>
              form.getFieldValue("client_type") === "confidential" ? (
                <Form.Item
                  name="client_secret"
                  label="Client Secret"
                  tooltip={{ title: tip("client_secret"), icon: <ExclamationCircleOutlined /> }}
                >
                  <Input.Password placeholder="Auto-generated if left empty" autoComplete="new-password" />
                </Form.Item>
              ) : null
            }
          </Form.Item>

          <Form.List
            name="redirect_uris"
            rules={[
              {
                validator: async (_, uris) => {
                  if (!uris || uris.length === 0) {
                    return Promise.reject("At least one redirect URI required");
                  }
                },
              },
            ]}
          >
            {(fields, { add, remove }, { errors }) => (
              <>
                {fields.map((field) => (
                  <Form.Item
                    key={field.key}
                    label={field.name === 0 ? "Redirect URIs" : undefined}
                    required={field.name === 0}
                    tooltip={field.name === 0 ? { title: tip("redirect_uris"), icon: <ExclamationCircleOutlined /> } : undefined}
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
                        <Input
                          placeholder="https://example.com/callback"
                          style={{ width: "100%" }}
                        />
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

          <Form.List name="post_logout_redirect_uris">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <Form.Item
                    key={field.key}
                    label={field.name === 0 ? "Post-Logout Redirect URIs" : undefined}
                    tooltip={field.name === 0 ? { title: tip("post_logout_redirect_uris"), icon: <ExclamationCircleOutlined /> } : undefined}
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
                        <Input
                          placeholder="https://example.com/logout-callback"
                          style={{ width: "100%" }}
                        />
                      </Form.Item>
                      <Button
                        icon={<MinusCircleOutlined />}
                        onClick={() => remove(field.name)}
                      />
                    </Space.Compact>
                  </Form.Item>
                ))}
                <Form.Item
                  label={fields.length === 0 ? "Post-Logout Redirect URIs" : undefined}
                  tooltip={fields.length === 0 ? { title: tip("post_logout_redirect_uris"), icon: <ExclamationCircleOutlined /> } : undefined}
                >
                  <Button
                    type="dashed"
                    onClick={() => add()}
                    block
                    icon={<PlusOutlined />}
                  >
                    Add Post-Logout Redirect URI
                  </Button>
                </Form.Item>
              </>
            )}
          </Form.List>

          <Form.Item
            name="grant_types"
            label="Grant Types"
            tooltip={{ title: tip("grant_types"), icon: <ExclamationCircleOutlined /> }}
          >
            <Select mode="multiple" options={GRANT_TYPE_OPTIONS} />
          </Form.Item>

          <Form.Item
            name="response_types"
            label="Response Types"
            tooltip={{ title: tip("response_types"), icon: <ExclamationCircleOutlined /> }}
          >
            <Select mode="multiple" options={RESPONSE_TYPE_OPTIONS} />
          </Form.Item>

          <Form.Item
            name="scopes"
            label="Scopes"
            tooltip={{ title: tip("scopes"), icon: <ExclamationCircleOutlined /> }}
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
            tooltip={{ title: tip("token_endpoint_auth_method"), icon: <ExclamationCircleOutlined /> }}
          >
            <Select options={AUTH_METHOD_OPTIONS} />
          </Form.Item>

          <Divider />

          <Collapse
            items={[
              {
                key: "overrides",
                label: <Typography.Text strong>Configuration Overrides</Typography.Text>,
                children: (
                  <Space direction="vertical" style={{ width: "100%" }}>
                    <Form.Item
                      label="Access Token Expiration"
                      name="access_token_expiration"
                      tooltip={{ title: overrideTip("access_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Input placeholder="Global default (e.g. 15m)" />
                    </Form.Item>

                    <Form.Item
                      label="Refresh Token Expiration"
                      name="refresh_token_expiration"
                      tooltip={{ title: overrideTip("refresh_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Input placeholder="Global default (e.g. 720h)" />
                    </Form.Item>

                    <Form.Item
                      label="Auth Code Expiration"
                      name="authorization_code_expiration"
                      tooltip={{ title: overrideTip("authorization_code_expiration"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Input placeholder="Global default (e.g. 10m)" />
                    </Form.Item>

                    <Form.Item
                      label="Allowed Audiences"
                      name="allowed_audiences"
                      tooltip={{ title: overrideTip("allowed_audiences"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Select mode="tags" placeholder="Add audiences..." />
                    </Form.Item>

                    <Form.Item
                      label="Allow Self Signup"
                      name="allow_self_signup"
                      valuePropName="checked"
                      tooltip={{ title: overrideTip("allow_self_signup"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Switch />
                    </Form.Item>

                    <Form.Item
                      label="SSO Session Idle Timeout"
                      name="sso_session_idle_timeout"
                      tooltip={{ title: overrideTip("sso_session_idle_timeout"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Input placeholder="Global default (e.g. 30m)" />
                    </Form.Item>

                    <Form.Item
                      label="Trust Device Enabled"
                      name="trust_device_enabled"
                      valuePropName="checked"
                      tooltip={{ title: overrideTip("trust_device_enabled"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Switch />
                    </Form.Item>

                    <Form.Item
                      label="Trust Device Expiration"
                      name="trust_device_expiration"
                      tooltip={{ title: overrideTip("trust_device_expiration"), icon: <ExclamationCircleOutlined /> }}
                    >
                      <Input placeholder="Global default (e.g. 720h)" />
                    </Form.Item>

                    <Form.Item
                      label="Consent Required"
                      name="consent_required"
                      valuePropName="checked"
                      tooltip={{ title: "When enabled, users must grant consent before this client can access their information", icon: <ExclamationCircleOutlined /> }}
                    >
                      <Switch />
                    </Form.Item>
                  </Space>
                ),
              },
            ]}
          />
        </Form>
      </Drawer>

      <Modal
        title="Client Created Successfully"
        open={!!secretModal}
        onOk={() => setSecretModal(null)}
        onCancel={() => setSecretModal(null)}
        footer={[
          <Button key="copy" icon={<CopyOutlined />} onClick={handleCopySecret}>
            Copy Secret
          </Button>,
          <Button
            key="ok"
            type="primary"
            onClick={() => setSecretModal(null)}
          >
            Done
          </Button>,
        ]}
      >
        <Alert
          type="warning"
          message="Save this secret now. It will not be shown again."
          style={{ marginBottom: 16 }}
        />
        <Typography.Paragraph>
          <strong>Client ID:</strong>
        </Typography.Paragraph>
        <Typography.Paragraph copyable code>
          {secretModal?.client_id}
        </Typography.Paragraph>
        <Typography.Paragraph>
          <strong>Client Secret:</strong>
        </Typography.Paragraph>
        <Typography.Paragraph copyable code>
          {secretModal?.client_secret}
        </Typography.Paragraph>
      </Modal>
    </>
  );
}
