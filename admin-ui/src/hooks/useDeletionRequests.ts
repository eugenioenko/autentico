import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listDeletionRequests,
  approveDeletionRequest,
  cancelDeletionRequest,
} from "../api/deletion";
import type { ListParams } from "../api/users";

const DELETION_REQUESTS_KEY = ["deletion-requests"] as const;

export function useDeletionRequests(params?: ListParams) {
  return useQuery({
    queryKey: [...DELETION_REQUESTS_KEY, params],
    queryFn: () => listDeletionRequests(params),
  });
}

export function useApproveDeletionRequest() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => approveDeletionRequest(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: DELETION_REQUESTS_KEY });
    },
  });
}

export function useAdminCancelDeletionRequest() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => cancelDeletionRequest(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: DELETION_REQUESTS_KEY });
    },
  });
}
