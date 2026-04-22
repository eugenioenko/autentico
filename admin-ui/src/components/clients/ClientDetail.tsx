import { Drawer, Descriptions, Tag, Space, Typography } from "antd";
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
        <Descriptions.Item label="Post-Logout Redirect URIs">
          {client.post_logout_redirect_uris && client.post_logout_redirect_uris.length > 0 ? (
            <Space direction="vertical" size={4}>
              {client.post_logout_redirect_uris.map((uri) => (
                <span key={uri}>{uri}</span>
              ))}
            </Space>
          ) : (
            <span style={{ color: "#999" }}>None</span>
          )}
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
        <Descriptions.Item label="Scopes">
          <Space size={[0, 4]} wrap>
            {client.scopes?.split(" ").filter(Boolean).map((s) => (
              <Tag key={s}>{s}</Tag>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Auth Method">
          {client.token_endpoint_auth_method}
        </Descriptions.Item>
        <Descriptions.Item label="Admin Service Account">
          {client.is_admin_service_account ? (
            <Tag color="red">Enabled — client_credentials token grants admin API access</Tag>
          ) : (
            <Tag>Disabled</Tag>
          )}
        </Descriptions.Item>
      </Descriptions>

      {(client.access_token_expiration ||
        client.refresh_token_expiration ||
        client.authorization_code_expiration ||
        client.allowed_audiences?.length ||
        client.allow_self_signup !== undefined ||
        client.sso_session_idle_timeout ||
        client.trust_device_enabled !== undefined ||
        client.trust_device_expiration) && (
        <>
          <Typography.Title level={5} style={{ marginTop: 24 }}>
            Overrides
          </Typography.Title>
          <Descriptions column={1} bordered size="small">
            {client.access_token_expiration && (
              <Descriptions.Item label="Access Token TTL">
                {client.access_token_expiration}
              </Descriptions.Item>
            )}
            {client.refresh_token_expiration && (
              <Descriptions.Item label="Refresh Token TTL">
                {client.refresh_token_expiration}
              </Descriptions.Item>
            )}
            {client.authorization_code_expiration && (
              <Descriptions.Item label="Auth Code TTL">
                {client.authorization_code_expiration}
              </Descriptions.Item>
            )}
            {client.allowed_audiences?.length ? (
              <Descriptions.Item label="Allowed Audiences">
                {client.allowed_audiences.join(", ")}
              </Descriptions.Item>
            ) : null}
            {client.allow_self_signup !== undefined && (
              <Descriptions.Item label="Self Signup">
                {client.allow_self_signup ? "Allowed" : "Disabled"}
              </Descriptions.Item>
            )}
            {client.sso_session_idle_timeout && (
              <Descriptions.Item label="SSO Idle Timeout">
                {client.sso_session_idle_timeout}
              </Descriptions.Item>
            )}
            {client.trust_device_enabled !== undefined && (
              <Descriptions.Item label="Trust Device">
                {client.trust_device_enabled ? "Enabled" : "Disabled"}
              </Descriptions.Item>
            )}
            {client.trust_device_expiration && (
              <Descriptions.Item label="Trust Device TTL">
                {client.trust_device_expiration}
              </Descriptions.Item>
            )}
          </Descriptions>
        </>
      )}
    </Drawer>
  );
}
