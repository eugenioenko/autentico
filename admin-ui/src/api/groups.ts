import apiClient from "./client";
import type { ListParams, ListResponse } from "./users";
import type {
  Group,
  GroupCreateRequest,
  GroupUpdateRequest,
  GroupMember,
} from "../types/group";

const BASE = "/admin/api/groups";

export async function listGroups(
  params?: ListParams
): Promise<ListResponse<Group>> {
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
  const { data } = await apiClient.get<{ data: ListResponse<Group> }>(url);
  return data.data;
}

export async function getGroup(id: string): Promise<Group> {
  const { data } = await apiClient.get<{ data: Group }>(`${BASE}/${id}`);
  return data.data;
}

export async function createGroup(request: GroupCreateRequest): Promise<Group> {
  const { data } = await apiClient.post<{ data: Group }>(BASE, request);
  return data.data;
}

export async function updateGroup(
  id: string,
  request: GroupUpdateRequest
): Promise<Group> {
  const { data } = await apiClient.put<{ data: Group }>(
    `${BASE}/${id}`,
    request
  );
  return data.data;
}

export async function deleteGroup(id: string): Promise<void> {
  await apiClient.delete(`${BASE}/${id}`);
}

export async function listMembers(groupId: string): Promise<GroupMember[]> {
  const { data } = await apiClient.get<{ data: GroupMember[] }>(
    `${BASE}/${groupId}/members`
  );
  return data.data;
}

export async function addMember(
  groupId: string,
  userId: string
): Promise<void> {
  await apiClient.post(`${BASE}/${groupId}/members`, { user_id: userId });
}

export async function removeMember(
  groupId: string,
  userId: string
): Promise<void> {
  await apiClient.delete(`${BASE}/${groupId}/members/${userId}`);
}

export async function getUserGroups(userId: string): Promise<Group[]> {
  const { data } = await apiClient.get<{ data: Group[] }>(
    `/admin/api/users/${userId}/groups`
  );
  return data.data;
}
