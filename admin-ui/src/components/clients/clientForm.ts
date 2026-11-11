export interface UriItem {
  value: string;
}

export interface ClientFormValues {
  client_name: string;
  client_id?: string;
  client_type?: string;
  client_secret?: string;
  is_active?: boolean;
  redirect_uris: UriItem[];
  post_logout_redirect_uris: UriItem[];
  grant_types: string[];
  response_types: string[];
  scopes: string[];
  token_endpoint_auth_method?: string;
  access_token_expiration?: string;
  refresh_token_expiration?: string;
  authorization_code_expiration?: string;
  allowed_audiences?: string[];
  allow_self_signup?: boolean;
  sso_session_idle_timeout?: string;
  trust_device_enabled?: boolean;
  trust_device_expiration?: string;
  consent_required?: boolean;
  show_in_account?: boolean;
  client_uri?: string;
  logo_uri?: string;
  description?: string;
  restrict_access?: boolean;
  allowed_groups?: string[];
  allowed_users?: string[];
}

export const GRANT_TYPE_OPTIONS = [
  { label: "Authorization Code", value: "authorization_code" },
  { label: "Refresh Token", value: "refresh_token" },
  { label: "Client Credentials", value: "client_credentials" },
  { label: "Password", value: "password" },
  { label: "Device Code", value: "urn:ietf:params:oauth:grant-type:device_code" },
];

export const RESPONSE_TYPE_OPTIONS = [{ label: "Code", value: "code" }];

export const CLIENT_TYPE_OPTIONS = [
  { label: "Confidential", value: "confidential" },
  { label: "Public", value: "public" },
];

const AUTH_METHOD_OPTIONS = [
  { label: "Client Secret Basic", value: "client_secret_basic" },
  { label: "Client Secret Post", value: "client_secret_post" },
  { label: "None", value: "none" },
];

export function authMethodOptions(clientType: string | undefined) {
  return AUTH_METHOD_OPTIONS.filter((option) => (option.value === "none") === (clientType === "public"));
}

export const SCOPE_OPTIONS = [
  { label: "openid", value: "openid" },
  { label: "profile", value: "profile" },
  { label: "email", value: "email" },
  { label: "address", value: "address" },
  { label: "phone", value: "phone" },
  { label: "offline_access", value: "offline_access" },
  { label: "groups", value: "groups" },
  { label: "custom_claims", value: "custom_claims" },
];

export function toUriItems(uris: string[] | undefined): UriItem[] {
  return (uris ?? []).map((value) => ({ value }));
}

export function toClientRequest(values: ClientFormValues) {
  const { redirect_uris, post_logout_redirect_uris, scopes, restrict_access, allowed_groups, allowed_users, ...rest } = values;
  return {
    ...rest,
    restrict_access: !!restrict_access,
    allowed_groups: allowed_groups ?? [],
    allowed_users: allowed_users ?? [],
    redirect_uris: redirect_uris.map((uri) => uri.value),
    post_logout_redirect_uris: post_logout_redirect_uris.map((uri) => uri.value),
    scopes: scopes?.join(" "),
  };
}
