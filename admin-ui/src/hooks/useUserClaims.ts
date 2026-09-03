import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getUserClaims,
  upsertUserClaim,
  deleteUserClaim,
} from "../api/userClaims";
import type { UserClaimRequest } from "../types/userClaim";

export function useUserClaims(userId: string | null, enabled = true) {
  return useQuery({
    queryKey: ["user-claims", userId],
    queryFn: () => getUserClaims(userId!),
    enabled: !!userId && enabled,
  });
}

export function useUpsertUserClaim() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      userId,
      claim,
    }: {
      userId: string;
      claim: UserClaimRequest;
    }) => upsertUserClaim(userId, claim),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["user-claims", variables.userId],
      });
    },
  });
}

export function useDeleteUserClaim() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, name }: { userId: string; name: string }) =>
      deleteUserClaim(userId, name),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["user-claims", variables.userId],
      });
    },
  });
}
