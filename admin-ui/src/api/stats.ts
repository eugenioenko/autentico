import apiClient from "./client";

export interface StatsResponse {
  total_users: number;
  active_clients: number;
  active_devices: number;
  active_tokens: number;
  recent_logins: number;
  pending_deletion_requests: number;
  failed_logins_24h: number;
  locked_accounts: number;
}

export async function getStats(): Promise<StatsResponse> {
  const { data } = await apiClient.get<{ data: StatsResponse }>(
    "/admin/api/stats"
  );
  return data.data;
}
