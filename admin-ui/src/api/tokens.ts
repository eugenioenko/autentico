import apiClient from "./client";
import type { ListParams, ListResponse } from "./users";
import type { AdminTokenResponse } from "../types/token";

const BASE = "/admin/api/tokens";

export async function listTokens(
  params?: ListParams
): Promise<ListResponse<AdminTokenResponse>> {
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
    data: ListResponse<AdminTokenResponse>;
  }>(url);
  return data.data;
}

export async function revokeToken(id: string): Promise<void> {
  await apiClient.delete(`${BASE}/${id}`);
}
