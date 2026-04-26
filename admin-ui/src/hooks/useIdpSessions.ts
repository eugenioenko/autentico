import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listIdpSessions,
  listUserIdpSessions,
  forceLogoutIdpSession,
  listIdpSessionSessions,
  deactivateOAuthSession,
  revokeAllUserSessions,
} from "../api/idpSessions";
import type { ListParams } from "../api/users";

const IDP_SESSIONS_KEY = ["idp-sessions"] as const;
const OAUTH_SESSIONS_KEY = ["oauth-sessions"] as const;

export function useIdpSessions(params?: ListParams) {
  return useQuery({
    queryKey: [...IDP_SESSIONS_KEY, params],
    queryFn: () => listIdpSessions(params),
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

export function useIdpSessionSessions(
  idpSessionId: string | null,
  params?: ListParams
) {
  return useQuery({
    queryKey: [...OAUTH_SESSIONS_KEY, idpSessionId, params],
    queryFn: () => listIdpSessionSessions(idpSessionId!, params),
    enabled: !!idpSessionId,
  });
}

export function useDeactivateOAuthSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deactivateOAuthSession(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: OAUTH_SESSIONS_KEY });
      queryClient.invalidateQueries({ queryKey: IDP_SESSIONS_KEY });
    },
  });
}

export function useRevokeAllUserSessions() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => revokeAllUserSessions(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: IDP_SESSIONS_KEY });
      queryClient.invalidateQueries({ queryKey: OAUTH_SESSIONS_KEY });
    },
  });
}
