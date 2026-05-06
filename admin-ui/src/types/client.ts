import type { components } from "./api";

export type ClientCreateRequest =
  components["schemas"]["client.ClientCreateRequest"] & {
    client_id?: string;
    access_token_expiration?: string;
    refresh_token_expiration?: string;
    authorization_code_expiration?: string;
    allowed_audiences?: string[];
    allow_self_signup?: boolean;
    sso_session_idle_timeout?: string;
    trust_device_enabled?: boolean;
    trust_device_expiration?: string;
    consent_required?: boolean;
  };

export type ClientUpdateRequest =
  components["schemas"]["client.ClientUpdateRequest"] & {
    access_token_expiration?: string;
    refresh_token_expiration?: string;
    authorization_code_expiration?: string;
    allowed_audiences?: string[];
    allow_self_signup?: boolean;
    sso_session_idle_timeout?: string;
    trust_device_enabled?: boolean;
    trust_device_expiration?: string;
    consent_required?: boolean;
  };

export type ClientResponse = components["schemas"]["client.ClientResponse"];

export type ClientInfoResponse =
  components["schemas"]["client.ClientInfoResponse"] & {
    access_token_expiration?: string;
    refresh_token_expiration?: string;
    authorization_code_expiration?: string;
    allowed_audiences?: string[];
    allow_self_signup?: boolean;
    sso_session_idle_timeout?: string;
    trust_device_enabled?: boolean;
    trust_device_expiration?: string;
    consent_required?: boolean;
  };
