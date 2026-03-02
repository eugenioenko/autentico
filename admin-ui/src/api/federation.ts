import apiClient from "./client";
import type {
  FederationProvider,
  FederationProviderCreateRequest,
  FederationProviderUpdateRequest,
} from "../types/federation";

const BASE = "/admin/api/federation";

export async function listFederationProviders(): Promise<FederationProvider[]> {
  const { data } = await apiClient.get<FederationProvider[]>(BASE);
  return data;
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
