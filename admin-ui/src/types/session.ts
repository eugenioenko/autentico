// SessionResponse is not in swagger spec yet — defined manually to match Go SessionResponse
export interface SessionResponse {
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
  status: "active" | "expired" | "deactivated";
}
