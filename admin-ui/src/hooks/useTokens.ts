import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listTokens, revokeToken } from "../api/tokens";
import type { ListParams } from "../api/users";

const TOKENS_KEY = ["tokens"] as const;

export function useTokens(params?: ListParams) {
  return useQuery({
    queryKey: [...TOKENS_KEY, params],
    queryFn: () => listTokens(params),
  });
}

export function useRevokeToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => revokeToken(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: TOKENS_KEY });
    },
  });
}
