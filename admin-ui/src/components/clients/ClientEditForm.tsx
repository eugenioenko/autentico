import { useEffect } from "react";
import {
  Drawer,
  Form,
  Input,
  Select,
  Button,
  Space,
  Divider,
  Collapse,
  Switch,
  Typography,
  Alert,
  App,
} from "antd";
import { PlusOutlined, MinusCircleOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
import { tip, overrideTip } from "./clientTips";
import { useUpdateClient } from "../../hooks/useClients";
import type {
  ClientInfoResponse,
  ClientUpdateRequest,
} from "../../types/client";
import { useTranslation } from "react-i18next";

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
  { label: "Device Code", value: "urn:ietf:params:oauth:grant-type:device_code" },
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
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const updateClient = useUpdateClient();

  useEffect(() => {
    if (client && open) {
      form.setFieldsValue({
        client_name: client.client_name,
        is_active: client.is_active,
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
        consent_required: client.consent_required,
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
      message.success(t("clients.clientUpdated"));
      onClose();
      } catch {
      message.error(t("clients.updateClientFailed"));
    }
  };

  return (
    <Drawer
      title={t("clients.editClientTitle", { name: client?.client_name ?? "" })}
      open={open}
      onClose={onClose}
      width={520}
      extra={
        <Space>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={updateClient.isPending}
          >
            {t("common.save")}
          </Button>
        </Space>
      }
    >
      <Form form={form} layout="vertical" onFinish={handleSubmit}>
        <Form.Item
          name="client_name"
          label={t("clients.clientName")}
          rules={[{ required: true, message: t("clients.clientNameRequired") }]}
          tooltip={{ title: tip("client_name"), icon: <ExclamationCircleOutlined /> }}
        >
          <Input />
        </Form.Item>

        <Form.Item
          label={t("clients.clientId")}
          tooltip={{ title: tip("client_id"), icon: <ExclamationCircleOutlined /> }}
        >
          <Input value={client?.client_id} disabled />
        </Form.Item>

        <Form.Item
          name="is_active"
          label={t("common.status")}
          valuePropName="checked"
        >
          <Switch
            checkedChildren={t("common.active")}
            unCheckedChildren={t("common.inactive")}
          />
        </Form.Item>

        <Form.Item noStyle shouldUpdate={(prev, cur) => prev.is_active !== cur.is_active}>
          {() =>
            !form.getFieldValue("is_active") && (
              <Alert
                type="warning"
                message={t("clients.disabledWarning")}
                showIcon
                style={{ marginBottom: 24 }}
              />
            )
          }
        </Form.Item>

        <Form.List name="redirect_uris">
          {(fields, { add, remove }, { errors }) => (
            <>
              {fields.map((field) => (
                <Form.Item
                  key={field.key}
                  label={field.name === 0 ? t("clients.redirectUris") : undefined}
                  required={field.name === 0}
                  tooltip={field.name === 0 ? { title: tip("redirect_uris"), icon: <ExclamationCircleOutlined /> } : undefined}
                >
                  <Space.Compact style={{ width: "100%" }}>
                    <Form.Item
                      {...field}
                      noStyle
                      rules={[
                        { required: true, message: t("clients.uriRequired") },
                        { type: "url", message: t("clients.mustBeValidUrl") },
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
                  {t("clients.addRedirectUri")}
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
                  label={field.name === 0 ? t("clients.postLogoutRedirectUri") : undefined}
                  tooltip={field.name === 0 ? { title: tip("post_logout_redirect_uris"), icon: <ExclamationCircleOutlined /> } : undefined}
                >
                  <Space.Compact style={{ width: "100%" }}>
                    <Form.Item
                      {...field}
                      noStyle
                      rules={[
                        { required: true, message: t("clients.uriRequired") },
                        { type: "url", message: t("clients.mustBeValidUrl") },
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
                label={fields.length === 0 ? t("clients.postLogoutRedirectUri") : undefined}
                tooltip={fields.length === 0 ? { title: tip("post_logout_redirect_uris"), icon: <ExclamationCircleOutlined /> } : undefined}
              >
                <Button
                  type="dashed"
                  onClick={() => add()}
                  block
                  icon={<PlusOutlined />}
                >
                  {t("clients.addPostLogoutRedirectUri")}
                </Button>
              </Form.Item>
            </>
          )}
        </Form.List>

        <Form.Item
          name="grant_types"
          label={t("clients.grantType")}
          tooltip={{ title: tip("grant_types"), icon: <ExclamationCircleOutlined /> }}
        >
          <Select mode="multiple" options={GRANT_TYPE_OPTIONS} />
        </Form.Item>

        <Form.Item
          name="response_types"
          label={t("clients.responseType")}
          tooltip={{ title: tip("response_types"), icon: <ExclamationCircleOutlined /> }}
        >
          <Select mode="multiple" options={RESPONSE_TYPE_OPTIONS} />
        </Form.Item>

        <Form.Item
          name="scopes"
          label={t("clients.scope")}
          tooltip={{ title: tip("scopes"), icon: <ExclamationCircleOutlined /> }}
        >
          <Select
            mode="tags"
            options={SCOPE_OPTIONS}
            placeholder={t("clients.scope") + "..."}
          />
        </Form.Item>

        <Form.Item
          name="token_endpoint_auth_method"
          label={t("clients.tokenEndpointAuthMethod")}
          tooltip={{ title: tip("token_endpoint_auth_method"), icon: <ExclamationCircleOutlined /> }}
        >
          <Select options={AUTH_METHOD_OPTIONS} />
        </Form.Item>

        <Divider />

        <Collapse
          items={[
            {
              key: "overrides",
              label: <Typography.Text strong>{t("clients.overridesLabel")}</Typography.Text>,
              children: (
                <Space direction="vertical" style={{ width: "100%" }}>
                  <Form.Item
                    label={t("settings.accessTokenExpiration")}
                    name="access_token_expiration"
                    tooltip={{ title: overrideTip("access_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder={t("clients.globalDefaultPlaceholder")} />
                  </Form.Item>

                  <Form.Item
                    label={t("settings.refreshTokenExpiration")}
                    name="refresh_token_expiration"
                    tooltip={{ title: overrideTip("refresh_token_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder={t("clients.globalDefaultPlaceholder")} />
                  </Form.Item>

                  <Form.Item
                    label={t("settings.authorizationCodeExpiration")}
                    name="authorization_code_expiration"
                    tooltip={{ title: overrideTip("authorization_code_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder={t("clients.globalDefaultPlaceholder")} />
                  </Form.Item>

                  <Form.Item
                    label={t("clients.allowedAudiences")}
                    name="allowed_audiences"
                    tooltip={{ title: overrideTip("allowed_audiences"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Select mode="tags" placeholder={t("clients.allowedAudiences") + "..."} />
                  </Form.Item>

                  <Form.Item
                    label={t("settings.allowSelfSignup")}
                    name="allow_self_signup"
                    valuePropName="checked"
                    tooltip={{ title: overrideTip("allow_self_signup"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label={t("clients.ssoIdleTimeout")}
                    name="sso_session_idle_timeout"
                    tooltip={{ title: overrideTip("sso_session_idle_timeout"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder={t("clients.globalDefaultPlaceholder")} />
                  </Form.Item>

                  <Form.Item
                    label={t("clients.trustedDevice")}
                    name="trust_device_enabled"
                    valuePropName="checked"
                    tooltip={{ title: overrideTip("trust_device_enabled"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    label={t("clients.trustedDeviceTtl")}
                    name="trust_device_expiration"
                    tooltip={{ title: overrideTip("trust_device_expiration"), icon: <ExclamationCircleOutlined /> }}
                  >
                    <Input placeholder={t("clients.globalDefaultPlaceholder")} />
                  </Form.Item>

                  <Form.Item
                    label={t("clients.consentRequired")}
                    name="consent_required"
                    valuePropName="checked"
                    tooltip={{ title: t("clients.consentRequiredTooltip"), icon: <ExclamationCircleOutlined /> }}
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
  );
}
