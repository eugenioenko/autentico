import apiClient from "./client";
import type { IdpSessionResponse } from "../types/idpSession";

export async function listIdpSessions(
  userId?: string
): Promise<IdpSessionResponse[]> {
  const params = userId ? { user_id: userId } : undefined;
  const { data } = await apiClient.get<{ data: IdpSessionResponse[] }>(
    "/admin/api/idp-sessions",
    { params }
  );
  return data.data;
}

export async function listUserIdpSessions(
  userId: string
): Promise<IdpSessionResponse[]> {
  const { data } = await apiClient.get<{ data: IdpSessionResponse[] }>(
    `/admin/api/users/${userId}/idp-sessions`
  );
  return data.data;
}

export async function forceLogoutIdpSession(id: string): Promise<void> {
  await apiClient.delete(`/admin/api/idp-sessions/${id}`);
}
