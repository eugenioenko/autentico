import { useMemo } from "react";
import { Badge, Button, Drawer, Inline, Stack, Text, VisuallyHidden, toast } from "@yarcl/react";
import { IconLogout } from "@tabler/icons-react";
import { useUserIdpSessions, useForceLogoutIdpSession, useRevokeAllUserSessions } from "../../hooks/useIdpSessions";
import type { IdpSessionResponse } from "../../types/idpSession";
import { describeUserAgent, formatActiveAppsCount } from "../../lib/utils";
import { DataTable, dataColumns } from "../DataTable";
import Confirm from "../Confirm";
import ConfirmIconButton from "../ConfirmIconButton";

interface UserSessionsDrawerProps {
  open: boolean;
  userId: string | null;
  username: string;
  onClose: () => void;
}

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function UserSessionsDrawer({ open, userId, username, onClose }: UserSessionsDrawerProps) {
  const { data: sessions, isLoading } = useUserIdpSessions(open ? userId : null);
  const { mutateAsync: forceLogout } = useForceLogoutIdpSession();
  const revokeAll = useRevokeAllUserSessions();

  const handleRevokeAll = async () => {
    if (!userId) return;
    try {
      await revokeAll.mutateAsync(userId);
      toast({ title: "All sessions revoked", color: "success" });
    } catch {
      toast({ title: "Failed to revoke sessions", color: "danger" });
    }
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
      col.display({
        id: "device",
        header: "Device",
        cell: ({ row }) => (
          <Stack gap="xs">
            <Text textStyle="label">{describeUserAgent(row.original.user_agent)}</Text>
            <Text textStyle="caption" muted>
              {row.original.ip_address || "Unknown IP"}
            </Text>
          </Stack>
        ),
      }),
      col.accessor("active_apps_count", {
        id: "apps",
        header: "Apps",
        enableSorting: false,
        meta: { width: 140 },
        cell: (info) => (
          <Badge variant="soft" color={info.getValue() > 0 ? "info" : "neutral"}>
            {formatActiveAppsCount(info.getValue())}
          </Badge>
        ),
      }),
      col.accessor("last_activity_at", {
        header: "Last Active",
        enableSorting: false,
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.accessor("created_at", {
        header: "Signed In",
        enableSorting: false,
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.display({
        id: "actions",
        header: () => <VisuallyHidden>Actions</VisuallyHidden>,
        meta: { width: 50 },
        cell: ({ row }) => (
          <ConfirmIconButton
            tooltip="Force sign out device"
            aria-label="Force sign out device"
            color="danger"
            icon={<IconLogout />}
            title="Force sign out this device?"
            description="This will revoke all sessions and tokens from this device."
            confirmLabel="Sign Out"
            onConfirm={() => handleForceLogout(row.original.id)}
          />
        ),
      }),
    ]);
  }, [forceLogout]);

  return (
    <Drawer title={`Sessions for ${username}`} open={open} onOpenChange={(next) => !next && onClose()} side="right" size="lg">
      <Stack gap="md">
        <Inline gap="sm" justify="between" align="center">
          <Text muted>Active devices where this user is signed in.</Text>
          <Confirm
            title="Revoke all sessions?"
            description="This will revoke all tokens, sessions, and sign out every device for this user."
            confirmLabel="Revoke All"
            onConfirm={handleRevokeAll}
          >
            <Button
              color="danger"
              variant="outline"
              size="sm"
              startIcon={<IconLogout />}
              loading={revokeAll.isPending}
              disabled={!sessions?.length}
            >
              Revoke All Sessions
            </Button>
          </Confirm>
        </Inline>

        <DataTable
          caption={`Sessions for ${username}`}
          data={sessions ?? []}
          columns={columns}
          getRowId={(s) => s.id}
          loading={isLoading}
          pageSize={false}
          emptyTitle="No active sessions"
        />
      </Stack>
    </Drawer>
  );
}
