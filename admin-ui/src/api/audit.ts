import apiClient from "./client";
import type { ListParams, ListResponse } from "./users";
import type { AuditLogEntry } from "../types/audit";

const BASE = "/admin/api/audit-logs";

export async function listAuditLogs(
  params?: ListParams
): Promise<ListResponse<AuditLogEntry>> {
  const query = new URLSearchParams();
  if (params) {
    for (const [key, val] of Object.entries(params)) {
      if (val !== undefined && val !== "") {
        query.set(key, String(val));
      }
    }
  }
  const qs = query.toString();
  const url = qs ? `${BASE}?${qs}` : BASE;
  const { data } = await apiClient.get<{
    data: ListResponse<AuditLogEntry>;
  }>(url);
  return data.data;
}
