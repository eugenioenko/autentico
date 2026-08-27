import apiClient from "./client";
import type { UserClaim, UserClaimRequest } from "../types/userClaim";

const base = (userId: string) => `/admin/api/users/${userId}/claims`;

export async function getUserClaims(userId: string): Promise<UserClaim[]> {
  const { data } = await apiClient.get<{ data: UserClaim[] }>(base(userId));
  return data.data;
}

export async function upsertUserClaim(
  userId: string,
  request: UserClaimRequest
): Promise<void> {
  await apiClient.post(base(userId), request);
}

export async function deleteUserClaim(
  userId: string,
  name: string
): Promise<void> {
  // Claim names may be namespaced URIs containing "/". Sent raw, net/http.ServeMux
  // path-cleans the "//" and 301-redirects, breaking the delete. Percent-encode the
  // whole name; the {name...} route decodes it back on the server.
  await apiClient.delete(`${base(userId)}/${encodeURIComponent(name)}`);
}
