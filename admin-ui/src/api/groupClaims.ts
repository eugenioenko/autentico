import apiClient from "./client";
import type { UserClaim, UserClaimRequest } from "../types/userClaim";

const base = (groupId: string) => `/admin/api/groups/${groupId}/claims`;

/** Lists local assignments without the group prefix added during claim emission. */
export async function getGroupClaims(groupId: string): Promise<UserClaim[]> {
  const { data } = await apiClient.get<{ data: UserClaim[] }>(base(groupId));
  return data.data;
}

/** Creates or replaces one validated local claim through the admin API. */
export async function upsertGroupClaim(
  groupId: string,
  request: UserClaimRequest
): Promise<void> {
  await apiClient.post(base(groupId), request);
}

/** Removes a local claim, encoding namespaced names for the catch-all API route. */
export async function deleteGroupClaim(
  groupId: string,
  name: string
): Promise<void> {
  // encoded: names may be namespaced URIs; raw "//" gets path-cleaned + redirected
  await apiClient.delete(`${base(groupId)}/${encodeURIComponent(name)}`);
}
