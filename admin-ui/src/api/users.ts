import apiClient from "./client";
import type {
  UserCreateRequest,
  UserUpdateRequest,
  UserResponseExt,
} from "../types/user";

const BASE = "/admin/api/users";

export async function listUsers(): Promise<UserResponseExt[]> {
  const { data } = await apiClient.get<{ data: UserResponseExt[] }>(BASE);
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
