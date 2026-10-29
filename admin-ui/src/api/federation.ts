import apiClient from "./client";
import type {
  FederationProvider,
  FederationProviderCreateRequest,
  FederationProviderUpdateRequest,
} from "../types/federation";
import type { ListParams, ListResponse } from "./users";
import type { ClaimRequirement, ClaimTestResult } from '../types/federation';

const BASE = "/admin/api/federation";

// Preserve the original sample JSON for the Go parser (including duplicate keys).
export async function testClaimRequirements(rules: ClaimRequirement[], claims: string): Promise<ClaimTestResult> {
  JSON.parse(claims);
  const { data } = await apiClient.post<ClaimTestResult>(`${BASE}/test-claim-requirements`,
    `{"claim_requirements":${JSON.stringify(rules)},"claims":${claims}}`, { headers: { 'Content-Type': 'application/json' } });
  return data;
}

export async function validateClaimRequirements(_: unknown, rules?: ClaimRequirement[]) {
  if (!rules?.length) return;
  const result = await testClaimRequirements(rules, '{}');
  const invalid = result.results.find(row => row.reason.startsWith('invalid_') || row.reason === 'pattern_too_long');
  if (invalid) throw new Error(`Row ${invalid.index + 1}: ${invalid.reason.split('_').join(' ')}`);
}

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
