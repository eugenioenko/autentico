import apiClient from "./client";
import type { ListParams, ListResponse } from "./users";

const BASE = "/admin/api/deletion-requests";

export interface DeletionRequestResponse {
  id: string;
  user_id: string;
  username: string;
  email: string;
  reason?: string;
  requested_at: string;
}

export async function listDeletionRequests(
  params?: ListParams
): Promise<ListResponse<DeletionRequestResponse>> {
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
    data: ListResponse<DeletionRequestResponse>;
  }>(url);
  return data.data;
}

export async function approveDeletionRequest(id: string): Promise<void> {
  await apiClient.post(`${BASE}/${id}/approve`);
}

export async function cancelDeletionRequest(id: string): Promise<void> {
  await apiClient.delete(`${BASE}/${id}`);
}
