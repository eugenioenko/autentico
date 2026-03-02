export interface FederationProvider {
  id: string;
  name: string;
  issuer: string;
  client_id: string;
  icon_svg: string;
  enabled: boolean;
  sort_order: number;
}

export interface FederationProviderCreateRequest {
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
  name: string;
  issuer: string;
  client_id: string;
  client_secret?: string;
  icon_svg?: string;
  enabled?: boolean;
  sort_order?: number;
}
