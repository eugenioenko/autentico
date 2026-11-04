import { useMemo, useState } from "react";
import { Alert, Badge, Button, IconButton, Inline, Stack, Tooltip, toast } from "@yarcl/react";
import { IconEdit, IconPlus, IconTrash } from "@tabler/icons-react";
import { useFederationProviders, useDeleteFederationProvider } from "../hooks/useFederation";
import type { FederationProvider } from "../types/federation";
import type { ListParams } from "../api/users";
import FederationCreateForm from "../components/federation/FederationCreateForm";
import FederationEditForm from "../components/federation/FederationEditForm";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import CopyText from "../components/CopyText";
import SearchInput from "../components/SearchInput";
import ConfirmIconButton from "../components/ConfirmIconButton";
import { DataTable, dataColumns, type DataFilter } from "../components/DataTable";

const filters: DataFilter[] = [
  {
    key: "enabled",
    label: "Status",
    allLabel: "All statuses",
    options: [
      { value: "1", label: "Enabled" },
      { value: "0", label: "Disabled" },
    ],
  },
];

export default function FederationPage() {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "sort_order",
    order: "asc",
  });

  const { data, isLoading, error } = useFederationProviders(listParams);
  const deleteProvider = useDeleteFederationProvider();

  const [createOpen, setCreateOpen] = useState(false);
  const [editProvider, setEditProvider] = useState<FederationProvider | null>(null);

  const columns = useMemo(() => {
    const handleDelete = async (id: string) => {
      try {
        await deleteProvider.mutateAsync(id);
        toast({ title: "Provider deleted", color: "success" });
      } catch {
        toast({ title: "Failed to delete provider", color: "danger" });
      }
    };
    const col = dataColumns<FederationProvider>();
    return col.columns([
      col.accessor("name", { header: "Name", cell: (info) => <CopyText text={info.getValue()} /> }),
      col.accessor("issuer", { header: "Issuer", cell: (info) => <CopyText text={info.getValue()} /> }),
      col.accessor("client_id", { header: "Client ID", cell: (info) => <CopyText text={info.getValue()} /> }),
      col.accessor("enabled", {
        header: "Status",
        meta: { width: 100 },
        cell: (info) => (
          <Badge variant="soft" color={info.getValue() ? "success" : "neutral"}>
            {info.getValue() ? "Enabled" : "Disabled"}
          </Badge>
        ),
      }),
      col.accessor("sort_order", { header: "Order", meta: { width: 80 } }),
      col.display({
        id: "actions",
        header: "Actions",
        cell: ({ row }) => (
          <Inline gap="xs" wrap={false}>
            <ConfirmIconButton
              tooltip="Delete provider"
              aria-label="Delete provider"
              icon={<IconTrash />}
              color="danger"
              title="Delete this provider?"
              description="Users who signed in via this provider will keep their accounts but won't be able to log in with it again."
              confirmLabel="Delete"
              onConfirm={() => handleDelete(row.original.id)}
            />
            <Tooltip content="Edit provider">
              <IconButton
                variant="ghost"
                color="neutral"
                size="sm"
                aria-label="Edit provider"
                onClick={() => setEditProvider(row.original)}
              >
                <IconEdit />
              </IconButton>
            </Tooltip>
          </Inline>
        ),
      }),
    ]);
  }, [deleteProvider]);

  if (error) {
    return <Alert color="danger" title="Failed to load federation providers" />;
  }

  return (
    <Stack gap="md">
      <DataTable
        toolbar={
          <SearchInput
            placeholder="Search name, issuer, or client ID..."
            onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
          />
        }
        actions={
          <Button startIcon={<IconPlus />} onClick={() => setCreateOpen(true)}>
            Add Provider
          </Button>
        }
        caption="Federation providers"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(p) => p.id}
        loading={isLoading}
        filters={filters}
        emptyTitle="No federation providers found"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} providers`,
        }}
      />

      <FederationCreateForm open={createOpen} onClose={() => setCreateOpen(false)} />
      <FederationEditForm open={!!editProvider} provider={editProvider} onClose={() => setEditProvider(null)} />
    </Stack>
  );
}
