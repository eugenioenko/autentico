import apiClient from "./client";
import type { SessionResponse } from "../types/session";

const BASE = "/admin/api/sessions";

export async function listSessions(
  userId?: string
): Promise<SessionResponse[]> {
  const params = userId ? { user_id: userId } : undefined;
  const { data } = await apiClient.get<{ data: SessionResponse[] }>(BASE, {
    params,
  });
  return data.data;
}

export async function deactivateSession(id: string): Promise<void> {
  await apiClient.delete(BASE, { params: { id } });
}
