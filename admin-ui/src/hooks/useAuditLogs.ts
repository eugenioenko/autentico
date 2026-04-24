import { useQuery } from "@tanstack/react-query";
import { listAuditLogs } from "../api/audit";
import type { ListParams } from "../api/users";

const AUDIT_KEY = ["audit-logs"] as const;

export function useAuditLogs(params?: ListParams) {
  return useQuery({
    queryKey: [...AUDIT_KEY, params],
    queryFn: () => listAuditLogs(params),
  });
}
