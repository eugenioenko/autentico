import { useState, useMemo } from "react";
import { Alert, Badge, Combobox, Drawer, IconButton, Stack, Text, Tooltip, VisuallyHidden, type Color, type DateRange } from "@yarcl/react";
import { IconEye } from "@tabler/icons-react";
import { useAuditLogs } from "../hooks/useAuditLogs";
import { useSettings } from "../hooks/useSettings";
import type { AuditLogEntry } from "../types/audit";
import type { ListParams } from "../api/users";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import CopyText from "../components/CopyText";
import DateRangeFilter, { dateRangeParams } from "../components/DateRangeFilter";
import DescriptionList from "../components/DescriptionList";
import SearchInput from "../components/SearchInput";
import { DataTable, dataColumns } from "../components/DataTable";
import "./AuditLogPage.css";

const ALL_EVENTS = "__all__";

const EVENT_OPTIONS = [
  { label: "All Events", value: ALL_EVENTS },
  { label: "Login Success", value: "login_success" },
  { label: "Login Failed", value: "login_failed" },
  { label: "MFA Success", value: "mfa_success" },
  { label: "MFA Failed", value: "mfa_failed" },
  { label: "Passkey Login Success", value: "passkey_login_success" },
  { label: "Passkey Login Failed", value: "passkey_login_failed" },
  { label: "Password Changed", value: "password_changed" },
  { label: "Password Reset Requested", value: "password_reset_requested" },
  { label: "Password Reset Completed", value: "password_reset_completed" },
  { label: "User Created", value: "user_created" },
  { label: "User Updated", value: "user_updated" },
  { label: "User Deactivated", value: "user_deactivated" },
  { label: "User Unlocked", value: "user_unlocked" },
  { label: "MFA Enrolled", value: "mfa_enrolled" },
  { label: "MFA Disabled", value: "mfa_disabled" },
  { label: "Passkey Added", value: "passkey_added" },
  { label: "Passkey Removed", value: "passkey_removed" },
  { label: "Logout", value: "logout" },
  { label: "Session Revoked", value: "session_revoked" },
  { label: "Client Created", value: "client_created" },
  { label: "Client Updated", value: "client_updated" },
  { label: "Client Deleted", value: "client_deleted" },
  { label: "Settings Updated", value: "settings_updated" },
  { label: "Settings Imported", value: "settings_imported" },
  { label: "Protected App Created", value: "protected_app_created" },
  { label: "Protected App Updated", value: "protected_app_updated" },
  { label: "Protected App Deleted", value: "protected_app_deleted" },
  { label: "Federation Created", value: "federation_created" },
  { label: "Federation Updated", value: "federation_updated" },
  { label: "Federation Deleted", value: "federation_deleted" },
  { label: "Deletion Approved", value: "deletion_approved" },
  { label: "Group Created", value: "group_created" },
  { label: "Group Updated", value: "group_updated" },
  { label: "Group Deleted", value: "group_deleted" },
  { label: "Group Member Added", value: "group_member_added" },
  { label: "Group Member Removed", value: "group_member_removed" },
  { label: "Group Claim Upserted", value: "group_claim_upserted" },
  { label: "Group Claim Deleted", value: "group_claim_deleted" },
  { label: "User Claim Upserted", value: "user_claim_upserted" },
  { label: "User Claim Deleted", value: "user_claim_deleted" },
];

const EVENT_COLORS: Record<string, Color> = {
  login_success: "success",
  login_failed: "danger",
  mfa_success: "success",
  mfa_failed: "danger",
  passkey_login_success: "success",
  passkey_login_failed: "danger",
  password_changed: "warning",
  password_reset_requested: "warning",
  password_reset_completed: "warning",
  user_created: "info",
  user_updated: "info",
  user_deactivated: "danger",
  user_unlocked: "info",
  mfa_enrolled: "info",
  mfa_disabled: "warning",
  passkey_added: "info",
  passkey_removed: "warning",
  logout: "neutral",
  session_revoked: "neutral",
  client_created: "info",
  client_updated: "info",
  client_deleted: "danger",
  settings_updated: "info",
  settings_imported: "info",
  federation_created: "info",
  federation_updated: "info",
  federation_deleted: "danger",
  deletion_approved: "danger",
  group_created: "info",
  group_updated: "info",
  group_deleted: "danger",
  group_member_added: "info",
  group_member_removed: "warning",
  group_claim_upserted: "info",
  group_claim_deleted: "warning",
  user_claim_upserted: "info",
  user_claim_deleted: "warning",
};

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

function formatEvent(event: string): string {
  return event.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function EventBadge({ event }: { event: string }) {
  return (
    <Badge variant="soft" color={EVENT_COLORS[event] ?? "neutral"}>
      {formatEvent(event)}
    </Badge>
  );
}

function Empty() {
  return <Text muted>—</Text>;
}

export default function AuditLogPage() {
  const { data: settings } = useSettings();
  const auditRetention = settings?.audit_log_retention ?? "0";
  const isDisabled = auditRetention === "0" || auditRetention === "";

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });
  const [eventFilter, setEventFilter] = useState(ALL_EVENTS);
  const [dateRange, setDateRange] = useState<DateRange | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);

  const { data, isLoading, error } = useAuditLogs(listParams);

  const eventLabel = EVENT_OPTIONS.find((o) => o.value === eventFilter)?.label;

  const handleEventFilter = (value: string | null) => {
    const next = value ?? ALL_EVENTS;
    setEventFilter(next);
    setListParams((prev) => ({ ...prev, event: next === ALL_EVENTS ? undefined : next, offset: 0 }));
  };

  const handleDateRange = (range: DateRange | null) => {
    setDateRange(range);
    setListParams((prev) => ({ ...prev, offset: 0, ...dateRangeParams(range, "created_at") }));
  };

  const columns = useMemo(() => {
    const col = dataColumns<AuditLogEntry>();
    return col.columns([
      col.accessor("event", {
        header: "Event",
        meta: { width: 200 },
        cell: (info) => <EventBadge event={info.getValue()} />,
      }),
      col.accessor("actor_username", {
        header: "Actor",
        enableSorting: false,
        meta: { width: 160 },
        cell: (info) => (info.getValue() ? <CopyText text={info.getValue()} /> : <Empty />),
      }),
      col.display({
        id: "target",
        header: "Target",
        meta: { width: 200 },
        cell: ({ row }) => {
          const record = row.original;
          if (!record.target_type && !record.target_id) return <Empty />;
          if (!record.target_id) return <Text truncate>{record.target_type}</Text>;
          return (
            <CopyText text={record.target_id}>
              {record.target_type}: {record.target_id}
            </CopyText>
          );
        },
      }),
      col.accessor("ip_address", {
        header: "IP",
        enableSorting: false,
        meta: { width: 130 },
        cell: (info) => info.getValue() || <Empty />,
      }),
      col.accessor("detail", {
        header: "Detail",
        enableSorting: false,
        cell: (info) =>
          info.getValue() ? (
            <Text textStyle="code" truncate className="audit-detail-cell" title={info.getValue()}>
              {info.getValue()}
            </Text>
          ) : (
            <Empty />
          ),
      }),
      col.accessor("created_at", {
        header: "Time",
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.display({
        id: "actions",
        header: () => <VisuallyHidden>Actions</VisuallyHidden>,
        meta: { width: 50 },
        cell: ({ row }) => (
          <Tooltip content="View details">
            <IconButton
              variant="ghost"
              color="neutral"
              size="sm"
              aria-label="View audit entry details"
              onClick={() => setSelectedEntry(row.original)}
            >
              <IconEye />
            </IconButton>
          </Tooltip>
        ),
      }),
    ]);
  }, []);

  if (error) return <Alert color="danger" title="Failed to load audit logs" />;

  return (
    <Stack gap="md">
      {isDisabled && (
        <Alert color="info" title="Audit logging is disabled">
          To start recording events, set the audit log retention in Settings &gt; Security &amp; Validation &gt; Audit Log
          (e.g. 720h for 30 days, or -1 to keep forever).
        </Alert>
      )}

      <DataTable
        toolbar={
          <>
            <SearchInput
              placeholder="Search actor, target, IP..."
              onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
            />
            <Combobox
              className="audit-event-filter"
              aria-label="Filter audit events"
              placeholder="All Events"
              options={EVENT_OPTIONS}
              value={eventFilter}
              onValueChange={handleEventFilter}
              filter={(option, text) =>
                !text || text === eventLabel || option.label.toLowerCase().includes(text.toLowerCase())
              }
            />
            <DateRangeFilter label="Date range" value={dateRange} onChange={handleDateRange} />
          </>
        }
        caption="Audit log"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(e) => e.id}
        loading={isLoading}
        emptyTitle="No audit events found"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} events`,
        }}
      />

      <Drawer
        title="Event Detail"
        open={!!selectedEntry}
        onOpenChange={(next) => !next && setSelectedEntry(null)}
        side="right"
        size="md"
      >
        {selectedEntry && (
          <DescriptionList>
            <DescriptionList.Item label="ID">{selectedEntry.id}</DescriptionList.Item>
            <DescriptionList.Item label="Event">
              <EventBadge event={selectedEntry.event} />
            </DescriptionList.Item>
            <DescriptionList.Item label="Time">{formatDate(selectedEntry.created_at)}</DescriptionList.Item>
            <DescriptionList.Item label="Actor ID">{selectedEntry.actor_id || "—"}</DescriptionList.Item>
            <DescriptionList.Item label="Actor Username">{selectedEntry.actor_username || "—"}</DescriptionList.Item>
            <DescriptionList.Item label="Target Type">{selectedEntry.target_type || "—"}</DescriptionList.Item>
            <DescriptionList.Item label="Target ID">{selectedEntry.target_id || "—"}</DescriptionList.Item>
            <DescriptionList.Item label="IP Address">{selectedEntry.ip_address || "—"}</DescriptionList.Item>
            <DescriptionList.Item label="Detail">
              {selectedEntry.detail ? (
                <Text as="div" textStyle="code" whiteSpace="pre-wrap" wrap="anywhere">
                  {JSON.stringify(JSON.parse(selectedEntry.detail), null, 2)}
                </Text>
              ) : (
                "—"
              )}
            </DescriptionList.Item>
          </DescriptionList>
        )}
      </Drawer>
    </Stack>
  );
}
