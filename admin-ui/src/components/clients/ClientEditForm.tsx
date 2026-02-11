import { useEffect } from "react";
import { Drawer, Form, Input, Select, Button, Space, message } from "antd";
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
        scopes: client.scopes,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
      });
    }
  }, [client, open, form]);

  const handleSubmit = async (values: ClientUpdateRequest) => {
    if (!client?.client_id) return;
    try {
      await updateClient.mutateAsync({
        clientId: client.client_id,
        data: values,
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

        <Form.Item name="scopes" label="Scopes">
          <Input />
        </Form.Item>

        <Form.Item
          name="token_endpoint_auth_method"
          label="Token Endpoint Auth Method"
        >
          <Select options={AUTH_METHOD_OPTIONS} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
