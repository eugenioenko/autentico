import { useState, useMemo } from "react";
import { Alert, Badge, Button, Drawer, IconButton, Inline, Select, Stack, Text, Tooltip, toast, type DateRange } from "@yarcl/react";
import { IconArrowLeft, IconInfoCircle, IconTrash } from "@tabler/icons-react";
import {
  useIdpSessions,
  useForceLogoutIdpSession,
  useIdpSessionSessions,
  useDeactivateOAuthSession,
} from "../hooks/useIdpSessions";
import type { ListParams } from "../api/users";
import type { IdpSessionResponse, OAuthSessionResponse } from "../types/idpSession";
import { describeUserAgent } from "../lib/utils";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import CopyText from "../components/CopyText";
import ConfirmIconButton from "../components/ConfirmIconButton";
import RowActionMenu from "../components/RowActionMenu";
import DateRangeFilter, { dateRangeParams } from "../components/DateRangeFilter";
import DescriptionList from "../components/DescriptionList";
import PageHeader from "../components/PageHeader";
import SearchInput from "../components/SearchInput";
import { DataTable, dataColumns } from "../components/DataTable";

function formatDate(date: string | null): string {
  if (!date) return "—";
  return new Date(date).toLocaleString();
}

function StatusBadge({ status }: { status: string }) {
  const color = status === "active" ? "success" : status === "expired" ? "warning" : "danger";
  return (
    <Badge variant="soft" color={color}>
      {status}
    </Badge>
  );
}

function DeviceCell({ session }: { session: IdpSessionResponse }) {
  return (
    <Stack gap="xs">
      <Text textStyle="label">{describeUserAgent(session.user_agent)}</Text>
      <Text textStyle="caption" muted>
        {session.ip_address || "Unknown IP"}
      </Text>
    </Stack>
  );
}

function OAuthSessionDetailDrawer({ session, onClose }: { session: OAuthSessionResponse | null; onClose: () => void }) {
  return (
    <Drawer title="Session Details" open={!!session} onOpenChange={(next) => !next && onClose()} side="right" size="md">
      {session && (
        <DescriptionList>
          <DescriptionList.Item label="Session ID">{session.id}</DescriptionList.Item>
          <DescriptionList.Item label="User ID">{session.user_id}</DescriptionList.Item>
          <DescriptionList.Item label="Status">
            <StatusBadge status={session.status} />
          </DescriptionList.Item>
          <DescriptionList.Item label="User Agent">{session.user_agent || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="IP Address">{session.ip_address || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Location">{session.location || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Device ID">{session.device_id || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Created">{formatDate(session.created_at)}</DescriptionList.Item>
          <DescriptionList.Item label="Expires">{formatDate(session.expires_at)}</DescriptionList.Item>
          <DescriptionList.Item label="Last Active">{formatDate(session.last_activity_at)}</DescriptionList.Item>
          <DescriptionList.Item label="Deactivated">{formatDate(session.deactivated_at)}</DescriptionList.Item>
        </DescriptionList>
      )}
    </Drawer>
  );
}

function SessionsView({ idpSession, onBack }: { idpSession: IdpSessionResponse; onBack: () => void }) {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });

  const { data, isLoading } = useIdpSessionSessions(idpSession.id, listParams);
  const { mutateAsync: deactivate } = useDeactivateOAuthSession();
  const [detailSession, setDetailSession] = useState<OAuthSessionResponse | null>(null);

  const columns = useMemo(() => {
    const handleDeactivate = async (id: string) => {
      try {
        await deactivate(id);
        toast({ title: "Session deactivated", color: "success" });
      } catch {
        toast({ title: "Failed to deactivate session", color: "danger" });
      }
    };

    const col = dataColumns<OAuthSessionResponse>();
    return col.columns([
      col.accessor("id", {
        header: "Session ID",
        enableSorting: false,
        meta: { width: 160 },
        cell: (info) => <CopyText text={info.getValue()}>{info.getValue().slice(0, 12) + "..."}</CopyText>,
      }),
      col.accessor("ip_address", {
        header: "IP Address",
        enableSorting: false,
        meta: { width: 140 },
        cell: (info) => info.getValue() || "—",
      }),
      col.accessor("status", {
        header: "Status",
        enableSorting: false,
        meta: { width: 110 },
        cell: (info) => <StatusBadge status={info.getValue()} />,
      }),
      col.accessor("created_at", {
        header: "Created",
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.accessor("expires_at", {
        header: "Expires",
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.display({
        id: "actions",
        header: "Actions",
        meta: { width: 80 },
        cell: ({ row }) => (
          <Inline gap="xs" wrap={false}>
            {row.original.status === "active" && (
              <ConfirmIconButton
                tooltip="Deactivate session"
                aria-label="Deactivate session"
                color="danger"
                icon={<IconTrash />}
                title="Deactivate this session?"
                confirmLabel="Deactivate"
                onConfirm={() => handleDeactivate(row.original.id)}
              />
            )}
            <Tooltip content="View details">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="View session details" onClick={() => setDetailSession(row.original)}>
                <IconInfoCircle />
              </IconButton>
            </Tooltip>
          </Inline>
        ),
      }),
    ]);
  }, [deactivate]);

  return (
    <Stack gap="md">
      <Inline>
        <Button variant="ghost" color="neutral" startIcon={<IconArrowLeft />} onClick={onBack}>
          Back to Sessions
        </Button>
      </Inline>
      <PageHeader
        title={`Sessions for ${idpSession.username || idpSession.user_id}`}
        description={`${describeUserAgent(idpSession.user_agent)} — ${idpSession.ip_address}`}
      />

      <DataTable
        caption="OAuth sessions"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(s) => s.id}
        loading={isLoading}
        emptyTitle="No sessions found"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} sessions`,
        }}
      />

      <OAuthSessionDetailDrawer session={detailSession} onClose={() => setDetailSession(null)} />
    </Stack>
  );
}

function IdpSessionDetailDrawer({ session, onClose }: { session: IdpSessionResponse | null; onClose: () => void }) {
  return (
    <Drawer title="Device Session Details" open={!!session} onOpenChange={(next) => !next && onClose()} side="right" size="md">
      {session && (
        <DescriptionList>
          <DescriptionList.Item label="Session ID">{session.id}</DescriptionList.Item>
          <DescriptionList.Item label="User ID">{session.user_id}</DescriptionList.Item>
          <DescriptionList.Item label="Username">{session.username}</DescriptionList.Item>
          <DescriptionList.Item label="Email">{session.email || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="User Agent">{session.user_agent || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="IP Address">{session.ip_address || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Active Apps">{session.active_apps_count}</DescriptionList.Item>
          <DescriptionList.Item label="Last Active">{formatDate(session.last_activity_at)}</DescriptionList.Item>
          <DescriptionList.Item label="Signed In">{formatDate(session.created_at)}</DescriptionList.Item>
        </DescriptionList>
      )}
    </Drawer>
  );
}

const DATE_FIELDS = [
  { label: "Last Active", value: "last_activity_at" },
  { label: "Signed In", value: "created_at" },
];

const DATE_FIELD_LABELS: Record<string, string> = {
  last_activity_at: "Last active between",
  created_at: "Signed in between",
};

export default function SessionsPage() {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "last_activity_at",
    order: "desc",
  });
  const [dateRange, setDateRange] = useState<DateRange | null>(null);
  const [dateField, setDateField] = useState<string>("last_activity_at");

  const { data, isLoading, error } = useIdpSessions(listParams);
  const { mutateAsync: forceLogout } = useForceLogoutIdpSession();

  const [sessionsIdp, setSessionsIdp] = useState<IdpSessionResponse | null>(null);
  const [detailSession, setDetailSession] = useState<IdpSessionResponse | null>(null);

  const handleDateRange = (range: DateRange | null, field: string) => {
    setDateRange(range);
    setListParams((prev) => ({
      ...prev,
      offset: 0,
      ...dateRangeParams(null, "created_at"),
      ...dateRangeParams(null, "last_activity_at"),
      ...dateRangeParams(range, field),
    }));
  };

  const columns = useMemo(() => {
    const handleForceLogout = async (id: string) => {
      try {
        await forceLogout(id);
        toast({ title: "Device signed out", color: "success" });
      } catch {
        toast({ title: "Failed to sign out device", color: "danger" });
      }
    };

    const col = dataColumns<IdpSessionResponse>();
    return col.columns([
      col.accessor("id", {
        header: "Session ID",
        enableSorting: false,
        meta: { width: 140 },
        cell: (info) => <CopyText text={info.getValue()}>{info.getValue().slice(0, 12) + "..."}</CopyText>,
      }),
      col.accessor("username", {
        header: "Username",
        enableSorting: false,
        meta: { width: 140 },
        cell: (info) => <Text truncate>{info.getValue()}</Text>,
      }),
      col.accessor("email", {
        header: "Email",
        enableSorting: false,
        cell: (info) => <CopyText text={info.getValue() ?? ""} />,
      }),
      col.display({
        id: "device",
        header: "Device",
        meta: { width: 200 },
        cell: ({ row }) => <DeviceCell session={row.original} />,
      }),
      col.accessor("active_apps_count", {
        id: "sessions",
        header: "Sessions",
        enableSorting: false,
        meta: { width: 90 },
        cell: (info) => (
          <Badge variant="soft" color={info.getValue() > 0 ? "info" : "neutral"}>
            {info.getValue()}
          </Badge>
        ),
      }),
      col.accessor("created_at", {
        header: "Signed In",
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.accessor("last_activity_at", {
        header: "Last Active",
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.display({
        id: "actions",
        header: "Actions",
        meta: { width: "1%" },
        cell: ({ row }) => (
          <Inline gap="xs" wrap={false}>
            <Tooltip content="View details">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="View device details" onClick={() => setDetailSession(row.original)}>
                <IconInfoCircle />
              </IconButton>
            </Tooltip>
            <RowActionMenu
              label={`More actions for device ${row.original.id}`}
              actions={[
                { label: "View OAuth sessions", onSelect: () => setSessionsIdp(row.original) },
                {
                  label: "Force sign out", danger: true, onSelect: () => handleForceLogout(row.original.id),
                  confirmation: { title: "Force sign out this device?", description: "This will revoke all sessions and tokens from this device.", confirmLabel: "Sign Out" },
                },
              ]}
            />
          </Inline>
        ),
      }),
    ]);
  }, [forceLogout]);

  if (sessionsIdp) {
    return <SessionsView idpSession={sessionsIdp} onBack={() => setSessionsIdp(null)} />;
  }

  if (error) {
    return <Alert color="danger" title="Failed to load sessions" />;
  }

  return (
    <Stack gap="md">
      <DataTable
        toolbar={
          <>
            <SearchInput
              placeholder="Search username, email, IP..."
              onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
            />
            <Select
              aria-label="Date field"
              options={DATE_FIELDS}
              value={dateField}
              onValueChange={(v) => {
                if (!v) return;
                setDateField(v);
                if (dateRange) handleDateRange(dateRange, v);
              }}
            />
            <DateRangeFilter label={DATE_FIELD_LABELS[dateField]} value={dateRange} onChange={(range) => handleDateRange(range, dateField)} />
          </>
        }
        caption="Sessions"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(s) => s.id}
        loading={isLoading}
        emptyTitle="No sessions found"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} sessions`,
        }}
      />

      <IdpSessionDetailDrawer session={detailSession} onClose={() => setDetailSession(null)} />
    </Stack>
  );
}
