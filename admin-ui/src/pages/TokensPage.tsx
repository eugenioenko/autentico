import { useState, useMemo } from "react";
import { Alert, Badge, Drawer, IconButton, Inline, Stack, Text, Tooltip, toast, type DateRange } from "@yarcl/react";
import { IconInfoCircle, IconTrash } from "@tabler/icons-react";
import { useTokens, useRevokeToken } from "../hooks/useTokens";
import type { ListParams } from "../api/users";
import type { AdminTokenResponse } from "../types/token";
import GrantChips from "../components/GrantChips";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import CopyText from "../components/CopyText";
import ConfirmIconButton from "../components/ConfirmIconButton";
import DateRangeFilter, { dateRangeParams } from "../components/DateRangeFilter";
import DescriptionList from "../components/DescriptionList";
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

function TokenDetailDrawer({ token, onClose }: { token: AdminTokenResponse | null; onClose: () => void }) {
  return (
    <Drawer title="Token Details" open={!!token} onOpenChange={(next) => !next && onClose()} side="right" size="md">
      {token && (
        <DescriptionList>
          <DescriptionList.Item label="Token ID">{token.id}</DescriptionList.Item>
          <DescriptionList.Item label="Status">
            <StatusBadge status={token.status} />
          </DescriptionList.Item>
          <DescriptionList.Item label="User ID">{token.user_id || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Username">{token.username || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Email">{token.email || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Grant Type">
            <GrantChips grants={[token.grant_type]} />
          </DescriptionList.Item>
          <DescriptionList.Item label="Scope">{token.scope || "—"}</DescriptionList.Item>
          <DescriptionList.Item label="Issued At">{formatDate(token.issued_at)}</DescriptionList.Item>
          <DescriptionList.Item label="Access Token Expires">{formatDate(token.access_token_expires_at)}</DescriptionList.Item>
          <DescriptionList.Item label="Revoked At">{formatDate(token.revoked_at)}</DescriptionList.Item>
        </DescriptionList>
      )}
    </Drawer>
  );
}

export default function TokensPage() {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "issued_at",
    order: "desc",
  });
  const [dateRange, setDateRange] = useState<DateRange | null>(null);

  const { data, isLoading, error } = useTokens(listParams);
  const { mutateAsync: revoke } = useRevokeToken();
  const [detailToken, setDetailToken] = useState<AdminTokenResponse | null>(null);

  const handleDateRange = (range: DateRange | null) => {
    setDateRange(range);
    setListParams((prev) => ({ ...prev, offset: 0, ...dateRangeParams(range, "issued_at") }));
  };

  const columns = useMemo(() => {
    const handleRevoke = async (id: string) => {
      try {
        await revoke(id);
        toast({ title: "Token revoked", color: "success" });
      } catch {
        toast({ title: "Failed to revoke token", color: "danger" });
      }
    };

    const col = dataColumns<AdminTokenResponse>();
    return col.columns([
      col.accessor("id", {
        header: "Token ID",
        enableSorting: false,
        meta: { width: 140 },
        cell: (info) => <CopyText text={info.getValue()}>{info.getValue().slice(0, 12) + "..."}</CopyText>,
      }),
      col.accessor("username", {
        header: "Username",
        enableSorting: false,
        meta: { width: 140 },
        cell: (info) => <Text truncate>{info.getValue() || "—"}</Text>,
      }),
      col.accessor("email", {
        header: "Email",
        enableSorting: false,
        cell: (info) => (info.getValue() ? <CopyText text={info.getValue()} /> : "—"),
      }),
      col.accessor("grant_type", {
        header: "Grant",
        enableSorting: false,
        meta: { width: 100 },
        cell: (info) => <GrantChips grants={[info.getValue()]} />,
      }),
      col.accessor("status", {
        header: "Status",
        enableSorting: false,
        meta: { width: 100 },
        cell: (info) => <StatusBadge status={info.getValue()} />,
      }),
      col.accessor("access_token_expires_at", {
        header: "Expires",
        meta: { width: 180 },
        cell: (info) => formatDate(info.getValue()),
      }),
      col.accessor("issued_at", {
        header: "Issued At",
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
                tooltip="Revoke token"
                aria-label="Revoke token"
                color="danger"
                icon={<IconTrash />}
                title="Revoke this token?"
                confirmLabel="Revoke"
                onConfirm={() => handleRevoke(row.original.id)}
              />
            )}
            <Tooltip content="View details">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="View token details" onClick={() => setDetailToken(row.original)}>
                <IconInfoCircle />
              </IconButton>
            </Tooltip>
          </Inline>
        ),
      }),
    ]);
  }, [revoke]);

  if (error) {
    return <Alert color="danger" title="Failed to load tokens" />;
  }

  return (
    <Stack gap="md">
      <DataTable
        toolbar={
          <>
            <SearchInput
              placeholder="Search username, email..."
              onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
            />
            <DateRangeFilter label="Issued between" value={dateRange} onChange={handleDateRange} />
          </>
        }
        caption="Tokens"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(t) => t.id}
        loading={isLoading}
        emptyTitle="No tokens found"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} tokens`,
        }}
      />

      <TokenDetailDrawer token={detailToken} onClose={() => setDetailToken(null)} />
    </Stack>
  );
}
