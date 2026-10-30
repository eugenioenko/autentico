import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getGroupClaims,
  upsertGroupClaim,
  deleteGroupClaim,
} from "../api/groupClaims";
import type { UserClaimRequest } from "../types/userClaim";

export function useGroupClaims(groupId: string | null, enabled = true) {
  return useQuery({
    queryKey: ["group-claims", groupId],
    queryFn: () => getGroupClaims(groupId!),
    enabled: !!groupId && enabled,
  });
}

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
