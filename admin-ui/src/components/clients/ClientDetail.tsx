import { Drawer, Descriptions, Tag, Space, Typography } from "antd";
import type { ClientInfoResponse } from "../../types/client";
import { useTranslation } from "react-i18next";

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
  const { t } = useTranslation();
  if (!client) return null;

  return (
    <Drawer
      title={t("clients.clientDetailTitle", { name: client.client_name })}
      open={open}
      onClose={onClose}
      width={520}
    >
      <Descriptions column={1} bordered size="small">
        <Descriptions.Item label={t("clients.clientId")}>
          {client.client_id}
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.clientName")}>
          {client.client_name}
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.clientType")}>
          <Tag color={client.client_type === "confidential" ? "blue" : "green"}>
            {client.client_type}
          </Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t("common.status")}>
          <Tag color={client.is_active ? "success" : "error"}>
            {client.is_active ? t("common.active") : t("common.inactive")}
          </Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.redirectUris")}>
          <Space direction="vertical" size={4}>
            {client.redirect_uris?.map((uri) => (
              <span key={uri}>{uri}</span>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.postLogoutRedirectUris")}>
          {client.post_logout_redirect_uris && client.post_logout_redirect_uris.length > 0 ? (
            <Space direction="vertical" size={4}>
              {client.post_logout_redirect_uris.map((uri) => (
                <span key={uri}>{uri}</span>
              ))}
            </Space>
          ) : (
            <span style={{ color: "#999" }}>{t("common.none")}</span>
          )}
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.grantType")}>
          <Space size={[0, 4]} wrap>
            {client.grant_types?.map((gt) => (
              <Tag key={gt}>{gt}</Tag>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.responseType")}>
          <Space size={[0, 4]} wrap>
            {client.response_types?.map((rt) => (
              <Tag key={rt}>{rt}</Tag>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.scope")}>
          <Space size={[0, 4]} wrap>
            {client.scopes?.split(" ").filter(Boolean).map((s) => (
              <Tag key={s}>{s}</Tag>
            ))}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label={t("clients.tokenEndpointAuthMethod")}>
          {client.token_endpoint_auth_method}
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
            {t("clients.overrides")}
          </Typography.Title>
          <Descriptions column={1} bordered size="small">
            {client.access_token_expiration && (
              <Descriptions.Item label={t("clients.accessTokenTtl")}>
                {client.access_token_expiration}
              </Descriptions.Item>
            )}
            {client.refresh_token_expiration && (
              <Descriptions.Item label={t("clients.refreshTokenTtl")}>
                {client.refresh_token_expiration}
              </Descriptions.Item>
            )}
            {client.authorization_code_expiration && (
              <Descriptions.Item label={t("clients.authorizationCodeTtl")}>
                {client.authorization_code_expiration}
              </Descriptions.Item>
            )}
            {client.allowed_audiences?.length ? (
              <Descriptions.Item label={t("clients.allowedAudiences")}>
                {client.allowed_audiences.join(", ")}
              </Descriptions.Item>
            ) : null}
            {client.allow_self_signup !== undefined && (
              <Descriptions.Item label={t("clients.selfSignup")}>
                {client.allow_self_signup ? t("common.enabled") : t("common.disabled")}
              </Descriptions.Item>
            )}
            {client.sso_session_idle_timeout && (
              <Descriptions.Item label={t("clients.ssoIdleTimeout")}>
                {client.sso_session_idle_timeout}
              </Descriptions.Item>
            )}
            {client.trust_device_enabled !== undefined && (
              <Descriptions.Item label={t("clients.trustedDevice")}>
                {client.trust_device_enabled ? t("common.enabled") : t("common.disabled")}
              </Descriptions.Item>
            )}
            {client.trust_device_expiration && (
              <Descriptions.Item label={t("clients.trustedDeviceTtl")}>
                {client.trust_device_expiration}
              </Descriptions.Item>
            )}
          </Descriptions>
        </>
      )}
    </Drawer>
  );
}
