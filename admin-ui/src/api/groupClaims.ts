import apiClient from "./client";
import type { UserClaim, UserClaimRequest } from "../types/userClaim";

const base = (groupId: string) => `/admin/api/groups/${groupId}/claims`;

export async function getGroupClaims(groupId: string): Promise<UserClaim[]> {
  const { data } = await apiClient.get<{ data: UserClaim[] }>(base(groupId));
  return data.data;
}

export async function upsertGroupClaim(
  groupId: string,
  request: UserClaimRequest
): Promise<void> {
  await apiClient.post(base(groupId), request);
}

export async function deleteGroupClaim(
  groupId: string,
  name: string
): Promise<void> {
  // encoded: names may be namespaced URIs; raw "//" gets path-cleaned + redirected
  await apiClient.delete(`${base(groupId)}/${encodeURIComponent(name)}`);
}
