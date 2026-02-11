import { Drawer, Descriptions, Tag, Space } from "antd";
import type { ClientInfoResponse } from "../../types/client";

interface ClientDetailProps {
  open: boolean;
  client: ClientInfoResponse | null;
  onClose: () => void;
}

export default function ClientDetail({
  open,
  client,
  onClose,
}: ClientDetailProps) {
  if (!client) return null;

  return (
    <Drawer
      title={`Client: ${client.client_name}`}
      open={open}
      onClose={onClose}
      width={520}
    >
      <Descriptions column={1} bordered size="small">
        <Descriptions.Item label="Client ID">
          {client.client_id}
        </Descriptions.Item>
        <Descriptions.Item label="Client Name">
          {client.client_name}
        </Descriptions.Item>
        <Descriptions.Item label="Client Type">
          <Tag color={client.client_type === "confidential" ? "blue" : "green"}>
            {client.client_type}
          </Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Status">
          <Tag color={client.is_active ? "success" : "error"}>
            {client.is_active ? "Active" : "Inactive"}
          </Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Redirect URIs">
          <Space direction="vertical" size={4}>
            {client.redirect_uris?.map((uri) => (
              <span key={uri}>{uri}</span>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Grant Types">
          <Space size={[0, 4]} wrap>
            {client.grant_types?.map((gt) => (
              <Tag key={gt}>{gt}</Tag>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Response Types">
          <Space size={[0, 4]} wrap>
            {client.response_types?.map((rt) => (
              <Tag key={rt}>{rt}</Tag>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Scopes">{client.scopes}</Descriptions.Item>
        <Descriptions.Item label="Auth Method">
          {client.token_endpoint_auth_method}
        </Descriptions.Item>
      </Descriptions>
    </Drawer>
  );
}
