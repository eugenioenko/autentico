import apiClient from "./client";

export interface StatsResponse {
  total_users: number;
  active_clients: number;
  active_sessions: number;
  total_sessions: number;
  recent_logins: number;
}

export async function getStats(): Promise<StatsResponse> {
  const { data } = await apiClient.get<{ data: StatsResponse }>(
    "/admin/api/stats"
  );
  return data.data;
}
