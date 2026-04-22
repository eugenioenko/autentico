import { useEffect } from "react";
import {
  Drawer,
  Form,
  Input,
  Select,
  Button,
  Space,
  message,
  Modal,
  Divider,
  Collapse,
  Switch,
  Typography,
} from "antd";
import { PlusOutlined, MinusCircleOutlined, ExclamationCircleOutlined } from "@ant-design/icons";

import { tip, overrideTip } from "./clientTips";
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
  const [modal, modalContextHolder] = Modal.useModal();

  useEffect(() => {
    if (client && open) {
      form.setFieldsValue({
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        post_logout_redirect_uris: client.post_logout_redirect_uris ?? [],
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
        is_admin_service_account: client.is_admin_service_account,
      });
    }
  }, [client, open, form]);

  const confirmServiceAccount = () =>
    new Promise<boolean>((resolve) => {
      modal.confirm({
        title: "Enable admin service account?",
        icon: <ExclamationCircleOutlined />,
        okText: "Yes, enable",
        okType: "danger",
        cancelText: "Cancel",
        content: (
          <div>
            <p>
              This client's <strong>client_secret</strong> becomes equivalent to
              admin bearer credentials. Any <code>client_credentials</code>{" "}
              token it obtains can call every endpoint under{" "}
              <code>/admin/api</code>.
            </p>
            <p>
              Store the secret in a secret manager and rotate it on leak. Only
              enable for headless automation that truly needs admin API access.
            </p>
          </div>
        ),
        onOk: () => resolve(true),
        onCancel: () => resolve(false),
      });
    });

  const handleSubmit = async (
    values: Omit<ClientUpdateRequest, "scopes"> & { scopes?: string[] },
  ) => {
    if (!client?.client_id) return;
    // Only prompt when flipping the flag from false → true. Editing an
    // already-elevated client shouldn't re-prompt on every save.
    if (
      values.is_admin_service_account &&
      !client.is_admin_service_account
    ) {
      const confirmed = await confirmServiceAccount();
      if (!confirmed) {
        return;
      }
    }
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
    <>
      {modalContextHolder}
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
          tooltip={{ title: tip("client_name"), icon: <ExclamationCircleOutlined /> }}
        >
          <Input />
        </Form.Item>

        <Form.Item
          label="Client ID"
          tooltip={{ title: tip("client_id"), icon: <ExclamationCircleOutlined /> }}
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
                      <Input style={{ width: "100%" }} />
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

        <Form.Item
          name="is_admin_service_account"
          label="Admin Service Account"
          valuePropName="checked"
          tooltip={{
            title:
              "When enabled, client_credentials tokens from this client can call the admin API without a user. Requires a confidential client with the client_credentials grant and autentico-admin in Allowed Audiences. The secret becomes equivalent to an admin bearer token.",
            icon: <ExclamationCircleOutlined />,
          }}
        >
          <Switch />
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
                </Space>
              ),
            },
          ]}
        />
      </Form>
    </Drawer>
    </>
  );
}
