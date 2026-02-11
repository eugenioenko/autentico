import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listSessions, deactivateSession } from "../api/sessions";

const SESSIONS_KEY = ["sessions"] as const;

export function useSessions(userId?: string) {
  return useQuery({
    queryKey: userId ? [...SESSIONS_KEY, userId] : [...SESSIONS_KEY],
    queryFn: () => listSessions(userId),
  });
}

export function useDeactivateSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deactivateSession(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: SESSIONS_KEY });
    },
  });
}
