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
  message,
} from "antd";
import {
  PlusOutlined,
  MinusCircleOutlined,
  CopyOutlined,
} from "@ant-design/icons";
import { useCreateClient } from "../../hooks/useClients";
import type { ClientCreateRequest, ClientResponse } from "../../types/client";

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

export default function ClientCreateForm({
  open,
  onClose,
}: ClientCreateFormProps) {
  const [form] = Form.useForm();
  const createClient = useCreateClient();
  const [secretModal, setSecretModal] = useState<ClientResponse | null>(null);

  const handleSubmit = async (values: ClientCreateRequest) => {
    try {
      const result = await createClient.mutateAsync(values);
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
            client_type: "confidential",
            grant_types: ["authorization_code"],
            response_types: ["code"],
            token_endpoint_auth_method: "client_secret_basic",
            scopes: "openid profile email",
            redirect_uris: [""],
          }}
        >
          <Form.Item
            name="client_name"
            label="Client Name"
            rules={[{ required: true, message: "Client name is required" }]}
          >
            <Input placeholder="My Application" />
          </Form.Item>

          <Form.Item name="client_type" label="Client Type">
            <Select options={CLIENT_TYPE_OPTIONS} />
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

          <Form.Item name="grant_types" label="Grant Types">
            <Select mode="multiple" options={GRANT_TYPE_OPTIONS} />
          </Form.Item>

          <Form.Item name="response_types" label="Response Types">
            <Select mode="multiple" options={RESPONSE_TYPE_OPTIONS} />
          </Form.Item>

          <Form.Item name="scopes" label="Scopes">
            <Input placeholder="openid profile email" />
          </Form.Item>

          <Form.Item
            name="token_endpoint_auth_method"
            label="Token Endpoint Auth Method"
          >
            <Select options={AUTH_METHOD_OPTIONS} />
          </Form.Item>
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
