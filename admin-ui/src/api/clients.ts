import apiClient from "./client";
import type {
  ClientCreateRequest,
  ClientUpdateRequest,
  ClientResponse,
  ClientInfoResponse,
} from "../types/client";
import type { ListParams, ListResponse } from "./users";

const BASE = "/admin/api/clients";

export async function listClients(
  params?: ListParams
): Promise<ListResponse<ClientInfoResponse>> {
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
    data: ListResponse<ClientInfoResponse>;
  }>(url);
  return data.data;
}

export async function getClient(clientId: string): Promise<ClientInfoResponse> {
  const { data } = await apiClient.get<ClientInfoResponse>(
    `${BASE}/${clientId}`
  );
  return data;
}

export async function createClient(
  request: ClientCreateRequest
): Promise<ClientResponse> {
  const { data } = await apiClient.post<ClientResponse>(BASE, request);
  return data;
}

export async function updateClient(
  clientId: string,
  request: ClientUpdateRequest
): Promise<ClientInfoResponse> {
  const { data } = await apiClient.put<ClientInfoResponse>(
    `${BASE}/${clientId}`,
    request
  );
  return data;
}

export async function deleteClient(clientId: string): Promise<void> {
  await apiClient.delete(`${BASE}/${clientId}`);
}
