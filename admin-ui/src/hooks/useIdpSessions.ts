import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listIdpSessions,
  listUserIdpSessions,
  forceLogoutIdpSession,
} from "../api/idpSessions";

const IDP_SESSIONS_KEY = ["idp-sessions"] as const;

export function useIdpSessions(userId?: string) {
  return useQuery({
    queryKey: userId ? [...IDP_SESSIONS_KEY, userId] : [...IDP_SESSIONS_KEY],
    queryFn: () => listIdpSessions(userId),
  });
}

export function useUserIdpSessions(userId: string | null) {
  return useQuery({
    queryKey: [...IDP_SESSIONS_KEY, "user", userId],
    queryFn: () => listUserIdpSessions(userId!),
    enabled: !!userId,
  });
}

export function useForceLogoutIdpSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => forceLogoutIdpSession(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: IDP_SESSIONS_KEY });
    },
  });
}
