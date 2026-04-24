export interface AuditLogEntry {
  id: string;
  event: string;
  actor_id: string | null;
  actor_username: string;
  target_type: string;
  target_id: string;
  detail: string;
  ip_address: string;
  created_at: string;
}
