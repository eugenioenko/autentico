import apiClient from "./client";
import type {
  UserCreateRequest,
  UserUpdateRequest,
  UserResponse,
} from "../types/user";

const BASE = "/admin/api/users";

export async function listUsers(): Promise<UserResponse[]> {
  const { data } = await apiClient.get<{ data: UserResponse[] }>(BASE);
  return data.data;
}

export async function getUser(id: string): Promise<UserResponse> {
  const { data } = await apiClient.get<{ data: UserResponse }>(BASE, {
    params: { id },
  });
  return data.data;
}

export async function createUser(
  request: UserCreateRequest
): Promise<UserResponse> {
  const { data } = await apiClient.post<{ data: UserResponse }>(BASE, request);
  return data.data;
}

export async function updateUser(
  id: string,
  request: UserUpdateRequest
): Promise<UserResponse> {
  const { data } = await apiClient.put<{ data: UserResponse }>(BASE, request, {
    params: { id },
  });
  return data.data;
}

export async function deleteUser(id: string): Promise<void> {
  await apiClient.delete(BASE, { params: { id } });
}
