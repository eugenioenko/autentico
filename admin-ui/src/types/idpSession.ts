export interface IdpSessionResponse {
  id: string;
  user_id: string;
  username: string;
  email: string;
  user_agent: string;
  ip_address: string;
  last_activity_at: string;
  created_at: string;
  active_apps_count: number;
}

export interface OAuthSessionResponse {
  id: string;
  user_id: string;
  user_agent: string;
  ip_address: string;
  device_id: string | null;
  last_activity_at: string | null;
  created_at: string;
  expires_at: string;
  deactivated_at: string | null;
  location: string;
  status: string;
}
