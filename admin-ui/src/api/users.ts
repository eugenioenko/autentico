import apiClient from "./client";
import type {
  UserCreateRequest,
  UserUpdateRequest,
  UserResponseExt,
} from "../types/user";

const BASE = "/admin/api/users";

export interface ListParams {
  sort?: string;
  order?: string;
  search?: string;
  limit?: number;
  offset?: number;
  [key: string]: string | number | undefined;
}

export interface ListResponse<T> {
  items: T[];
  total: number;
}

export async function listUsers(
  params?: ListParams
): Promise<ListResponse<UserResponseExt>> {
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
  const { data } = await apiClient.get<{ data: ListResponse<UserResponseExt> }>(url);
  return data.data;
}

export async function getUser(id: string): Promise<UserResponseExt> {
  const { data } = await apiClient.get<{ data: UserResponseExt }>(`${BASE}/${encodeURIComponent(id)}`);
  return data.data;
}

const LOOKUP_MAX_IDENTIFIERS = 100;

export async function lookupUsersByIds(ids: string[]): Promise<UserResponseExt[]> {
  const chunks: string[][] = [];
  for (let i = 0; i < ids.length; i += LOOKUP_MAX_IDENTIFIERS) {
    chunks.push(ids.slice(i, i + LOOKUP_MAX_IDENTIFIERS));
  }
  const results = await Promise.all(
    chunks.map(async (chunk) => {
      const { data } = await apiClient.post<{ data: { items: UserResponseExt[] } }>(`${BASE}/lookup`, { ids: chunk });
      return data.data.items ?? [];
    }),
  );
  return results.flat();
}

export async function createUser(
  request: UserCreateRequest
): Promise<UserResponseExt> {
  const { data } = await apiClient.post<{ data: UserResponseExt }>(BASE, request);
  return data.data;
}

export async function updateUser(
  id: string,
  request: UserUpdateRequest
): Promise<UserResponseExt> {
  const { data } = await apiClient.put<{ data: UserResponseExt }>(`${BASE}/${id}`, request);
  return data.data;
}

export async function deleteUser(id: string): Promise<void> {
  await apiClient.delete(`${BASE}/${id}`);
}

export async function unlockUser(id: string): Promise<UserResponseExt> {
  const { data } = await apiClient.post<{ data: UserResponseExt }>(
    `${BASE}/${id}/unlock`
  );
  return data.data;
}
