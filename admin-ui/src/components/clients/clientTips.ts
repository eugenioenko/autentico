import { makeTip } from "../../lib/tips";

// Tips for main client registration fields — links to registering.mdx
export const tip = makeTip({
  client_name: "Human-readable name for the client, shown in the Admin UI and logs.",
  client_id: "Custom client ID. Auto-generated if omitted. Must be unique across all clients.",
  client_type: "Confidential: server-side apps that can keep a secret. Public: browser or mobile apps that cannot — no secret is issued, use PKCE instead.",
  client_secret: "Optional. If left empty, a secret is auto-generated. Only shown once after creation.",
  redirect_uris: "Allowed callback URLs. The redirect_uri in each authorization request must exactly match one of these. No wildcards, max 10.",
  post_logout_redirect_uris: "Allowed URLs for OIDC RP-initiated logout. The post_logout_redirect_uri in a logout request must exactly match one of these. Optional — leave empty to disable RP-initiated logout redirects.",
  grant_types: "OAuth2 flows this client is permitted to use.",
  response_types: "What the authorization endpoint returns. Use [code] for the standard Authorization Code flow.",
  scopes: "Scopes the client is allowed to request. Standard: openid, profile, email, address, phone, offline_access.",
  token_endpoint_auth_method: "How the client authenticates at the token endpoint. Use none for public clients with PKCE.",
}, "https://autentico.top/clients/registering");

// Tips for per-client override fields — links to per-client-overrides.mdx
export const overrideTip = makeTip({
  access_token_expiration: "Override the access token lifetime for this client. Leave empty to use the global default.",
  refresh_token_expiration: "Override the refresh token lifetime for this client. Leave empty to use the global default.",
  authorization_code_expiration: "Override the authorization code TTL for this client. Leave empty to use the global default.",
  allowed_audiences: "Additional aud values added to access tokens issued to this client.",
  allow_self_signup: "Override the global allow_self_signup setting for this client's login page.",
  sso_session_idle_timeout: "Override the IdP session idle timeout for sessions from this client. Leave empty to use the global default.",
  trust_device_enabled: "Enable or disable trusted devices for users authenticating through this client.",
  trust_device_expiration: "Override the trusted device token lifetime for this client.",
}, "https://autentico.top/configuration/per-client-overrides");
