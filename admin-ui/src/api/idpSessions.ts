import apiClient from "./client";
import type { ListParams, ListResponse } from "./users";
import type {
  IdpSessionResponse,
  OAuthSessionResponse,
} from "../types/idpSession";

const BASE = "/admin/api/idp-sessions";

export async function listIdpSessions(
  params?: ListParams
): Promise<ListResponse<IdpSessionResponse>> {
  const query = new URLSearchParams();
  if (params) {
    for (const [key, val] of Object.entries(params)) {
      if (val !== undefined && val !== "") {
        query.set(key, String(val));
      }
    }
  }
  const qs = query.toString();
  const url = qs ? `${BASE}?${qs}` : BASE;
  const { data } = await apiClient.get<{
    data: ListResponse<IdpSessionResponse>;
  }>(url);
  return data.data;
}

export async function listIdpSessionSessions(
  idpSessionId: string,
  params?: ListParams
): Promise<ListResponse<OAuthSessionResponse>> {
  const query = new URLSearchParams();
  if (params) {
    for (const [key, val] of Object.entries(params)) {
      if (val !== undefined && val !== "") {
        query.set(key, String(val));
      }
    }
  }
  const qs = query.toString();
  const url = qs
    ? `${BASE}/${idpSessionId}/sessions?${qs}`
    : `${BASE}/${idpSessionId}/sessions`;
  const { data } = await apiClient.get<{
    data: ListResponse<OAuthSessionResponse>;
  }>(url);
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
  await apiClient.delete(`${BASE}/${id}`);
}

export async function deactivateOAuthSession(id: string): Promise<void> {
  await apiClient.delete(`/admin/api/sessions/${id}`);
}

export async function revokeAllUserSessions(userId: string): Promise<void> {
  await apiClient.post(`/admin/api/users/${userId}/revoke-sessions`);
}
