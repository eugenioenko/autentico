import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getGroupClaims,
  upsertGroupClaim,
  deleteGroupClaim,
} from "../api/groupClaims";
import type { UserClaimRequest } from "../types/userClaim";

/** Loads local claims only while a group is selected and loading is enabled. */
export function useGroupClaims(groupId: string | null, enabled = true) {
  return useQuery({
    queryKey: ["group-claims", groupId],
    queryFn: () => getGroupClaims(groupId!),
    enabled: !!groupId && enabled,
  });
}

/** Upserts a group claim and refreshes the selected group's cached assignments. */
export function useUpsertGroupClaim() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      groupId,
      claim,
    }: {
      groupId: string;
      claim: UserClaimRequest;
    }) => upsertGroupClaim(groupId, claim),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["group-claims", variables.groupId],
      });
    },
  });
}

/** Removes a group claim and refreshes that group's cached assignments. */
export function useDeleteGroupClaim() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ groupId, name }: { groupId: string; name: string }) =>
      deleteGroupClaim(groupId, name),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["group-claims", variables.groupId],
      });
    },
  });
}
