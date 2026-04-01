import { useQuery } from "@tanstack/react-query";
import { listAuditLogs, type AuditLogFilters } from "../api/audit";

const AUDIT_KEY = ["audit-logs"] as const;

export function useAuditLogs(filters: AuditLogFilters) {
  return useQuery({
    queryKey: [...AUDIT_KEY, filters],
    queryFn: () => listAuditLogs(filters),
  });
}
