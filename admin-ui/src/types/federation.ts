export type ClaimRequirement = { claim: string; match: 'equals' | 'not_equals' | 'regex' | 'not_regex'; value: string | boolean };
export type ClaimTestResult = { passed: boolean; results: { index: number; claim: string; match: string; passed: boolean; reason: string }[] };

export interface FederationProvider {
  claim_requirements?: ClaimRequirement[];
  claim_requirements_error?: string;
  id: string;
  name: string;
  issuer: string;
  client_id: string;
  icon_svg: string;
  enabled: boolean;
  sort_order: number;
}

export interface FederationProviderCreateRequest {
  claim_requirements?: ClaimRequirement[];
  id: string;
  name: string;
  issuer: string;
  client_id: string;
  client_secret: string;
  icon_svg?: string;
  enabled?: boolean;
  sort_order?: number;
}

export interface FederationProviderUpdateRequest {
  claim_requirements?: ClaimRequirement[];
  name: string;
  issuer: string;
  client_id: string;
  client_secret?: string;
  icon_svg?: string;
  enabled?: boolean;
  sort_order?: number;
}
