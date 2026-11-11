import { useState, useEffect, useMemo } from "react";
import { useLocation } from "react-router-dom";
import { Alert, Badge, Button, IconButton, Inline, Stack, Tooltip } from "@yarcl/react";
import { IconEdit, IconEye, IconPlus } from "@tabler/icons-react";
import { useClients } from "../hooks/useClients";
import type { ClientInfoResponse } from "../types/client";
import type { ListParams } from "../api/users";
import ClientCreateForm from "../components/clients/ClientCreateForm";
import ClientEditForm from "../components/clients/ClientEditForm";
import ClientDetail from "../components/clients/ClientDetail";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import GrantChips from "../components/GrantChips";
import CopyText from "../components/CopyText";
import SearchInput from "../components/SearchInput";
import { DataTable, dataColumns, type DataFilter } from "../components/DataTable";

const filters: DataFilter[] = [
  {
    key: "client_type",
    label: "Type",
    allLabel: "All types",
    options: [
      { value: "confidential", label: "Confidential" },
      { value: "public", label: "Public" },
    ],
  },
  {
    key: "is_active",
    label: "Status",
    allLabel: "All statuses",
    options: [
      { value: "1", label: "Active" },
      { value: "0", label: "Inactive" },
    ],
  },
];

export default function ClientsPage() {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });

  const { data, isLoading, error } = useClients(listParams);
  const location = useLocation();

  const [createOpen, setCreateOpen] = useState(false);

  useEffect(() => {
    if ((location.state as { create?: boolean })?.create) {
      setCreateOpen(true);
      window.history.replaceState({}, "");
    }
  }, [location.state]);
  const [editClient, setEditClient] = useState<ClientInfoResponse | null>(null);
  const [detailClient, setDetailClient] = useState<ClientInfoResponse | null>(null);

  const columns = useMemo(() => {
    const col = dataColumns<ClientInfoResponse>();
    return col.columns([
      col.accessor("client_name", {
        header: "Name",
        cell: (info) => <CopyText text={info.getValue() ?? ""} />,
      }),
      col.accessor("client_id", {
        header: "Client ID",
        cell: (info) => <CopyText text={info.getValue() ?? ""} />,
      }),
      col.accessor("client_type", {
        header: "Type",
        cell: (info) => (
          <Badge variant="soft" color={info.getValue() === "confidential" ? "info" : "success"}>
            {info.getValue()}
          </Badge>
        ),
      }),
      col.accessor("grant_types", {
        header: "Grants",
        enableSorting: false,
        cell: (info) => <GrantChips grants={info.getValue() ?? []} />,
      }),
      col.accessor("is_active", {
        header: "Status",
        enableSorting: false,
        cell: (info) => (
          <Inline gap="xs" wrap={false}>
            <Badge variant="soft" color={info.getValue() ? "success" : "danger"}>
              {info.getValue() ? "Active" : "Inactive"}
            </Badge>
            {info.row.original.restrict_access && (
              <Badge variant="soft" color="warning">
                Restricted
              </Badge>
            )}
          </Inline>
        ),
      }),
      col.display({
        id: "actions",
        header: "Actions",
        cell: ({ row }) => (
          <Inline gap="xs" wrap={false}>
            <Tooltip content="View details">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="View client details" onClick={() => setDetailClient(row.original)}>
                <IconEye />
              </IconButton>
            </Tooltip>
            <Tooltip content="Edit client">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="Edit client" onClick={() => setEditClient(row.original)}>
                <IconEdit />
              </IconButton>
            </Tooltip>
          </Inline>
        ),
      }),
    ]);
  }, []);

  if (error) {
    return <Alert color="danger" title="Failed to load clients" />;
  }

  return (
    <Stack gap="md">
      <DataTable
        toolbar={
          <SearchInput
            placeholder="Search name or client ID..."
            onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
          />
        }
        actions={
          <Button startIcon={<IconPlus />} onClick={() => setCreateOpen(true)}>
            Create Client
          </Button>
        }
        caption="Clients"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(c) => c.client_id ?? ""}
        loading={isLoading}
        filters={filters}
        emptyTitle="No clients found"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} clients`,
        }}
      />

      <ClientCreateForm open={createOpen} onClose={() => setCreateOpen(false)} />
      <ClientEditForm open={!!editClient} client={editClient} onClose={() => setEditClient(null)} />
      <ClientDetail open={!!detailClient} client={detailClient} onClose={() => setDetailClient(null)} />
    </Stack>
  );
}
