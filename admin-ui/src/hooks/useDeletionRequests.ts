import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listDeletionRequests,
  approveDeletionRequest,
  cancelDeletionRequest,
} from "../api/deletion";

const DELETION_REQUESTS_KEY = ["deletion-requests"] as const;

export function useDeletionRequests() {
  return useQuery({
    queryKey: DELETION_REQUESTS_KEY,
    queryFn: listDeletionRequests,
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
