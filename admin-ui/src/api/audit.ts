import apiClient from "./client";
import type { AuditLogListResponse } from "../types/audit";

const BASE = "/admin/api/audit-logs";

export interface AuditLogFilters {
  event?: string;
  actor_id?: string;
  limit?: number;
  offset?: number;
}

export async function listAuditLogs(
  filters: AuditLogFilters
): Promise<AuditLogListResponse> {
  const { data } = await apiClient.get<{ data: AuditLogListResponse }>(BASE, {
    params: filters,
  });
  return data.data;
}
