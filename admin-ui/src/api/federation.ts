import apiClient from "./client";
import type {
  FederationProvider,
  FederationProviderCreateRequest,
  FederationProviderUpdateRequest,
} from "../types/federation";
import type { ListParams, ListResponse } from "./users";

const BASE = "/admin/api/federation";

export async function listFederationProviders(
  params?: ListParams
): Promise<ListResponse<FederationProvider>> {
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
    data: ListResponse<FederationProvider>;
  }>(url);
  return data.data;
}

export async function createFederationProvider(
  request: FederationProviderCreateRequest
): Promise<void> {
  await apiClient.post(BASE, request);
}

export async function updateFederationProvider(
  id: string,
  request: FederationProviderUpdateRequest
): Promise<void> {
  await apiClient.put(`${BASE}/${id}`, request);
}

export async function deleteFederationProvider(id: string): Promise<void> {
  await apiClient.delete(`${BASE}/${id}`);
}
