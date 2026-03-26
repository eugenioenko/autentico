import apiClient from "./client";

const BASE = "/admin/api/deletion-requests";

export interface DeletionRequestResponse {
  id: string;
  user_id: string;
  reason?: string;
  requested_at: string;
}

export async function listDeletionRequests(): Promise<DeletionRequestResponse[]> {
  const { data } = await apiClient.get<{ data: DeletionRequestResponse[] }>(BASE);
  return data.data;
}

export async function approveDeletionRequest(id: string): Promise<void> {
  await apiClient.post(`${BASE}/${id}/approve`);
}

export async function cancelDeletionRequest(id: string): Promise<void> {
  await apiClient.delete(`${BASE}/${id}`);
}
