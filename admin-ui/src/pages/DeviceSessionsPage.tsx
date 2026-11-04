import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Alert, Badge, Button, Drawer, IconButton, Inline, Spinner, Stack, Text, Tooltip, toast } from "@yarcl/react";
import { IconArrowLeft, IconInfoCircle, IconTrash } from "@tabler/icons-react";
import { useUserIdpSessions, useIdpSessionSessions, useDeactivateOAuthSession } from "../hooks/useIdpSessions";
import type { ListParams } from "../api/users";
import type { IdpSessionResponse, OAuthSessionResponse } from "../types/idpSession";
import { describeUserAgent } from "../lib/utils";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import CopyText from "../components/CopyText";
import ConfirmIconButton from "../components/ConfirmIconButton";
import DescriptionList from "../components/DescriptionList";
import { DataTable, dataColumns } from "../components/DataTable";

function formatDate(date: string | null): string {
  return date ? new Date(date).toLocaleString() : "—";
}

function StatusBadge({ status }: { status: string }) {
  const color = status === "active" ? "success" : status === "expired" ? "warning" : "danger";
  return (
    <Badge variant="soft" color={color}>
      {status}
    </Badge>
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

export default function DeviceSessionsPage() {
  const { userId = "", sessionId = "" } = useParams();
  const navigate = useNavigate();
  const { data: devices, isLoading, error } = useUserIdpSessions(userId);
  const device = devices?.find((item) => item.id === sessionId);
  if (isLoading) return <div className="page-loading"><Spinner label="Loading device session" /></div>;
  if (error) return <Alert color="danger" title="Failed to load device session" />;
  if (!device) return <Alert color="danger" title="Device session not found" />;
  return <SessionsView key={device.id} idpSession={device} onBack={() => navigate("/sessions")} />;
}

function SessionsView({ idpSession, onBack }: { idpSession: IdpSessionResponse; onBack: () => void }) {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });

  const { data, isLoading, error } = useIdpSessionSessions(idpSession.id, listParams);
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

  if (error) return <Alert color="danger" title="Failed to load OAuth sessions" />;

  return (
    <Stack gap="md">
      <Inline gap="md" align="center">
        <Button className="admin-back-button" variant="ghost" color="neutral" startIcon={<IconArrowLeft />} onClick={onBack}>
          Back to Sessions
        </Button>
        <Text muted>{describeUserAgent(idpSession.user_agent)} — {idpSession.ip_address}</Text>
      </Inline>

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
