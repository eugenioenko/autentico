import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Alert, Badge, Button, Stack, toast, type DateRange } from "@yarcl/react";
import { IconPlus } from "@tabler/icons-react";
import apiClient from "../../api/client";
import type { ListParams } from "../../api/users";
import { DEFAULT_PAGE_SIZE } from "../../constants/table";
import CopyText from "../CopyText";
import { DataTable, dataColumns, type DataFilter } from "../DataTable";
import DateRangeFilter, { dateRangeParams } from "../DateRangeFilter";
import RowActionMenu, { type RowAction } from "../RowActionMenu";
import SearchInput from "../SearchInput";
import SignupInviteForm, { type InviteRequest } from "./SignupInviteForm";

const path = "/admin/api/signup-invites";

interface Invite {
  id: string;
  status: "active" | "revoked" | "expired" | "used";
  kind: "personal" | "shared";
  delivery_method: "link" | "email";
  email?: string;
  max_uses: number | null;
  use_count: number;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}
interface InviteList { items: Invite[]; total: number; smtp_available: boolean }

const filters: DataFilter[] = [
  { key: "kind", label: "Invitation type", allLabel: "All types", options: [
    { value: "personal", label: "Personal" }, { value: "shared", label: "Shared" },
  ] },
  { key: "delivery_method", label: "Delivery", allLabel: "Any delivery", options: [
    { value: "link", label: "Link" }, { value: "email", label: "Email" },
  ] },
  { key: "status", label: "Status", allLabel: "Any status", options: [
    { value: "active", label: "Active" }, { value: "revoked", label: "Revoked" },
    { value: "used", label: "Used" }, { value: "expired", label: "Expired" },
  ] },
];

const statusLabel = {active: "Active", revoked: "Revoked", expired: "Expired", used: "Used"};

const col = dataColumns<Invite>();
export default function SignupInvitesTab() {
  const queryClient = useQueryClient();
  const [params, setParams] = useState<ListParams>({limit: DEFAULT_PAGE_SIZE, offset: 0, sort: "created_at", order: "desc"});
  const [dates, setDates] = useState<DateRange | null>(null);
  const list = useQuery({
    queryKey: ["signup-invites", params],
    queryFn: async () => (await apiClient.get<{ data: InviteList }>(path, { params })).data.data,
  });
  const [open, setOpen] = useState(false);
  const [link, setLink] = useState<{ id: string; url: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err) {
      if (isAxiosError(err) && err.response?.data?.data?.id) setOpen(false);
      setError((isAxiosError(err) && err.response?.data?.error?.message) || "Invitation request failed.");
    } finally {
      await queryClient.invalidateQueries({queryKey: ["signup-invites"]});
      setBusy(false);
    }
  }
  function create(request: InviteRequest) {
    return run(async () => {
      const { data } = await apiClient.post(path, request);
      setLink(data.data.url ? data.data : null);
      setOpen(false);
      if (!data.data.url) toast({ title: "Invitation emailed", color: "success" });
    });
  }
  function rowActions(invite: Invite) {
    if (invite.status !== "active" || busy) return null;
    const actions: RowAction[] = [];
    if (invite.delivery_method === "email" && list.data?.smtp_available) {
      actions.push({ label: "Resend email", onSelect: () => run(async () => {
        await apiClient.post(path + "/" + invite.id + "/retry");
        toast({title: "New invitation emailed", color: "success"});
      }) });
    }
    actions.push({
      label: "Revoke", danger: true,
      confirmation: { title: "Revoke invitation?", description: "This link will stop accepting signups immediately.", confirmLabel: "Revoke" },
      onSelect: () => run(async () => {
        await apiClient.delete(path + "/" + invite.id);
        setLink(current => current?.id === invite.id ? null : current);
      }),
    });
    return <RowActionMenu label="Invitation actions" actions={actions} />;
  }
  const columns = col.columns([
    col.accessor("kind", {header: "Type", cell: info => info.getValue() === "shared" ? "Shared link" : "Personal"}),
    col.accessor("email", {header: "Recipient", cell: info => <CopyText text={info.getValue() ?? ""} />}),
    col.accessor("delivery_method", {header: "Delivery", cell: info => info.getValue() === "email" ? "Email" : "Link"}),
    col.accessor("use_count", {header: "Uses", cell: ({row}) => row.original.use_count + " of " + (row.original.max_uses ?? "unlimited") + " used"}),
    col.accessor("status", { header: "Status", cell: info =>
      <Badge variant="soft" color={info.getValue() === "active" ? "success" : "neutral"}>{statusLabel[info.getValue()]}</Badge>}),
    col.accessor("created_at", {header: "Created", cell: info => new Date(info.getValue()).toLocaleString()}),
    col.accessor("expires_at", {header: "Expires", cell: ({row}) => row.original.expires_at ? new Date(row.original.expires_at).toLocaleString() : "No expiration"}),
    col.display({id: "actions", cell: ({row}) => rowActions(row.original)}),
  ]);

  return (
    <Stack gap="md">
      {error && !open && <Alert color="danger" live="assertive">{error}</Alert>}
      {list.isError && <Alert color="danger">Could not load invitations.</Alert>}
      {link && <Alert color="success" title="Copy this signup link before leaving this page" onDismiss={() => setLink(null)}>
        <CopyText text={link.url} />
      </Alert>}
      <DataTable caption="Signup invites" columns={columns} data={list.data?.items ?? []} getRowId={i => i.id}
        loading={list.isLoading} emptyTitle="No invitations found" filters={filters}
        actions={<Button startIcon={<IconPlus />} onClick={() => { setError(""); setOpen(true); }}>Create invite</Button>}
        toolbar={<>
          <SearchInput placeholder="Search email or invite ID..." onSearch={search => setParams(p => ({...p, offset: 0, search: search || undefined}))} />
          <DateRangeFilter label="Created between" value={dates} onChange={range => {
            setDates(range);
            setParams(p => ({...p, offset: 0, ...dateRangeParams(range, "created_at")}));
          }} />
        </>}
        server={{params, onParamsChange: setParams, total: list.data?.total ?? 0, totalLabel: total => total === 1 ? "1 invitation" : total + " invitations"}} />
      {open && <SignupInviteForm smtp={!!list.data?.smtp_available} busy={busy} error={error} onClose={() => setOpen(false)} onCreate={create} />}
    </Stack>
  );
}
