import apiClient from "./client";
import type {
  ClientCreateRequest,
  ClientUpdateRequest,
  ClientResponse,
  ClientInfoResponse,
} from "../types/client";

const BASE = "/oauth2/register";

export async function listClients(): Promise<ClientInfoResponse[]> {
  const { data } = await apiClient.get<ClientInfoResponse[]>(BASE);
  return data;
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
