import { useState, useMemo } from "react";
import { Badge, Button, Dialog, Drawer, IconButton, Inline, Menu, Stack, Text, VisuallyHidden, toast } from "@yarcl/react";
import { IconDotsVertical } from "@tabler/icons-react";
import {
  useDeletionRequests,
  useApproveDeletionRequest,
  useAdminCancelDeletionRequest,
} from "../../hooks/useDeletionRequests";
import type { DeletionRequestResponse } from "../../api/deletion";
import type { ListParams } from "../../api/users";
import { DEFAULT_PAGE_SIZE } from "../../constants/table";
import CopyText from "../CopyText";
import DescriptionList from "../DescriptionList";
import SearchInput from "../SearchInput";
import { DataTable, dataColumns } from "../DataTable";

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

type PendingAction = { kind: "approve" | "dismiss"; request: DeletionRequestResponse };

const ACTION_COPY = {
  approve: {
    title: "Approve deletion?",
    description: "This will permanently delete the user account. This action cannot be undone.",
    confirmLabel: "Delete",
  },
  dismiss: {
    title: "Dismiss request?",
    description: "The user account will be kept and the request removed.",
    confirmLabel: "Dismiss",
  },
} as const;

export default function DeletionRequestsTab() {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "requested_at",
    order: "asc",
  });

  const { data, isLoading } = useDeletionRequests(listParams);
  const approve = useApproveDeletionRequest();
  const cancel = useAdminCancelDeletionRequest();

  const [detailRequest, setDetailRequest] = useState<DeletionRequestResponse | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);

  const handleConfirm = async () => {
    if (!pending) return;
    const { kind, request } = pending;
    try {
      if (kind === "approve") {
        await approve.mutateAsync(request.id);
        toast({ title: "User deleted successfully", color: "success" });
      } else {
        await cancel.mutateAsync(request.id);
        toast({ title: "Request dismissed", color: "success" });
      }
      setPending(null);
    } catch {
      toast({ title: kind === "approve" ? "Failed to approve deletion" : "Failed to dismiss request", color: "danger" });
    }
  };

  const columns = useMemo(() => {
    const col = dataColumns<DeletionRequestResponse>();
    return col.columns([
      col.accessor("username", {
        header: "Username",
        cell: (info) => <Text truncate>{info.getValue()}</Text>,
      }),
      col.accessor("email", {
        header: "Email",
        cell: (info) => <CopyText text={info.getValue() ?? ""} />,
      }),
      col.accessor("reason", {
        header: "Reason",
        enableSorting: false,
        meta: { width: 250 },
        cell: (info) =>
          info.getValue() ? (
            <Text truncate title={info.getValue()}>
              {info.getValue()}
            </Text>
          ) : (
            <Badge variant="soft" color="neutral">
              No reason
            </Badge>
          ),
      }),
      col.accessor("requested_at", {
        header: "Requested",
        cell: (info) => formatDate(info.getValue()),
      }),
      col.display({
        id: "actions",
        header: () => <VisuallyHidden>Actions</VisuallyHidden>,
        meta: { width: 50 },
        cell: ({ row }) => (
          <Menu placement="bottom-end">
            <Menu.Trigger>
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="More actions">
                <IconDotsVertical />
              </IconButton>
            </Menu.Trigger>
            <Menu.Content>
              <Menu.Item onSelect={() => setDetailRequest(row.original)}>View details</Menu.Item>
              <Menu.Item color="danger" onSelect={() => setPending({ kind: "approve", request: row.original })}>
                Approve deletion
              </Menu.Item>
              <Menu.Item onSelect={() => setPending({ kind: "dismiss", request: row.original })}>Dismiss request</Menu.Item>
            </Menu.Content>
          </Menu>
        ),
      }),
    ]);
  }, []);

  const pendingCopy = pending ? ACTION_COPY[pending.kind] : null;

  return (
    <Stack gap="md">
      <Inline gap="sm">
        <SearchInput
          placeholder="Search username, email, or reason..."
          onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
        />
      </Inline>

      <DataTable
        caption="Deletion requests"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(r) => r.id}
        loading={isLoading}
        emptyTitle="No pending deletion requests"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} requests`,
        }}
      />

      <Drawer
        title="Deletion Request"
        open={!!detailRequest}
        onOpenChange={(next) => !next && setDetailRequest(null)}
        side="right"
        size="md"
      >
        {detailRequest && (
          <DescriptionList>
            <DescriptionList.Item label="Username">{detailRequest.username}</DescriptionList.Item>
            <DescriptionList.Item label="Email">{detailRequest.email}</DescriptionList.Item>
            <DescriptionList.Item label="User ID">
              <CopyText text={detailRequest.user_id} />
            </DescriptionList.Item>
            <DescriptionList.Item label="Reason">{detailRequest.reason ?? "No reason provided"}</DescriptionList.Item>
            <DescriptionList.Item label="Requested at">{formatDate(detailRequest.requested_at)}</DescriptionList.Item>
          </DescriptionList>
        )}
      </Drawer>

      <Dialog
        title={pendingCopy?.title ?? ""}
        description={pendingCopy?.description}
        open={!!pending}
        onOpenChange={(next) => !next && setPending(null)}
        size="sm"
        footer={
          <>
            <Button variant="ghost" color="neutral" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button
              color={pending?.kind === "approve" ? "danger" : "primary"}
              loading={approve.isPending || cancel.isPending}
              onClick={handleConfirm}
            >
              {pendingCopy?.confirmLabel}
            </Button>
          </>
        }
      />
    </Stack>
  );
}
