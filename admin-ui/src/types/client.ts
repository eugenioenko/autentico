import type { components } from "./api";

export interface ClientAccess {
  restrict_access?: boolean;
  allowed_groups?: string[];
  allowed_users?: string[];
}

export type ClientCreateRequest =
  components["schemas"]["client.ClientCreateRequest"] &
  ClientAccess & {
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
    description?: string;
    logo_uri?: string;
    client_uri?: string;
    show_in_account?: boolean;
  };

export type ClientUpdateRequest =
  Omit<components["schemas"]["client.ClientUpdateRequest"],
    "access_token_expiration" | "refresh_token_expiration" | "authorization_code_expiration" |
    "allow_self_signup" | "sso_session_idle_timeout" | "trust_device_enabled" | "trust_device_expiration"> &
  ClientAccess & {
    // null clears the override (inherit global); omitted leaves it unchanged.
    access_token_expiration?: string | null;
    refresh_token_expiration?: string | null;
    authorization_code_expiration?: string | null;
    allowed_audiences?: string[];
    allow_self_signup?: boolean | null;
    sso_session_idle_timeout?: string | null;
    trust_device_enabled?: boolean | null;
    trust_device_expiration?: string | null;
    consent_required?: boolean;
    description?: string;
    logo_uri?: string;
    client_uri?: string;
    show_in_account?: boolean;
  };

export type ClientResponse = components["schemas"]["client.ClientResponse"];

export type ClientInfoResponse =
  components["schemas"]["client.ClientInfoResponse"] &
  ClientAccess & {
    access_token_expiration?: string;
    refresh_token_expiration?: string;
    authorization_code_expiration?: string;
    allowed_audiences?: string[];
    allow_self_signup?: boolean;
    sso_session_idle_timeout?: string;
    trust_device_enabled?: boolean;
    trust_device_expiration?: string;
    consent_required?: boolean;
    description?: string;
    logo_uri?: string;
    client_uri?: string;
    show_in_account?: boolean;
  };
