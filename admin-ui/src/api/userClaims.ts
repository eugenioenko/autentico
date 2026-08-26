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
  // Claim names may be namespaced URIs containing "/"; the DELETE route captures
  // the full remaining path, so the name is appended verbatim.
  await apiClient.delete(`${base(userId)}/${name}`);
}
