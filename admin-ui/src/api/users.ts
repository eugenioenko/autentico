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
  const { data } = await apiClient.get<{ data: UserResponseExt }>(`${BASE}/${id}`);
  return data.data;
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
