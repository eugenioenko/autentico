export interface AdminTokenResponse {
  id: string;
  user_id: string | null;
  username: string;
  email: string;
  scope: string;
  grant_type: string;
  access_token_expires_at: string;
  issued_at: string;
  revoked_at: string | null;
  status: string;
}
