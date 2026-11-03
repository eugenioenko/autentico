import { useCallback, useId, useMemo, useState } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { Alert, Badge, Button, Drawer, IconButton, Inline, Input, Stack, Switch, Textarea, Tooltip, toast } from "@yarcl/react";
import { IconEdit, IconPlus, IconTrash } from "@tabler/icons-react";
import apiClient from "../api/client";
import ConfirmIconButton from "../components/ConfirmIconButton";
import CopyText from "../components/CopyText";
import PageHeader from "../components/PageHeader";
import { FormField } from "../components/FormField";
import { DataTable, dataColumns } from "../components/DataTable";
import { urlRule } from "../lib/validation";

type ProtectedApp = {
  id: string; name: string; origin: string; allowed_return_paths: string[];
  client_id: string; session_ttl: string; is_active: boolean;
};
type Values = { name: string; origin: string; paths: string; session_ttl: string; is_active: boolean };
const endpoint = "/admin/api/protected-apps";
const DEFAULTS: Values = { name: "", origin: "", paths: "/", session_ttl: "8h", is_active: true };

export default function ProtectedAppsPage() {
  const formId = useId();
  const cache = useQueryClient();
  const { control, handleSubmit, reset } = useForm<Values>({ defaultValues: DEFAULTS });
  const [editing, setEditing] = useState<ProtectedApp | null>(null);
  const [open, setOpen] = useState(false);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["protected-apps"],
    queryFn: async () => (await apiClient.get<{ data: ProtectedApp[] }>(endpoint)).data.data,
  });
  const save = useMutation({
    mutationFn: async (values: Values) => {
      const body = { name: values.name, origin: values.origin, allowed_return_paths: values.paths.split("\n").map(p => p.trim()).filter(Boolean), session_ttl: values.session_ttl, is_active: values.is_active };
      return editing ? apiClient.put(`${endpoint}/${editing.id}`, body) : apiClient.post(endpoint, body);
    },
    onSuccess: () => { void cache.invalidateQueries({ queryKey: ["protected-apps"] }); setOpen(false); toast({ title: "Protected application saved", color: "success" }); },
    onError: (err: { response?: { data?: { error_description?: string } } }) => toast({ title: err.response?.data?.error_description ?? "Unable to save application", color: "danger" }),
  });
  const { mutateAsync: removeApp } = useMutation({
    mutationFn: (id: string) => apiClient.delete(`${endpoint}/${id}`),
    onSuccess: () => { void cache.invalidateQueries({ queryKey: ["protected-apps"] }); toast({ title: "Application deleted and sessions revoked", color: "success" }); },
    onError: () => toast({ title: "Unable to delete application", color: "danger" }),
  });

  const edit = useCallback((app: ProtectedApp | null) => {
    setEditing(app);
    reset(app ? { ...DEFAULTS, ...app, paths: app.allowed_return_paths.join("\n") } : DEFAULTS);
    setOpen(true);
  }, [reset]);

  const columns = useMemo(() => {
    const col = dataColumns<ProtectedApp>();
    return col.columns([
      col.accessor("name", { header: "Name", enableSorting: false }),
      col.accessor("origin", { header: "Origin", enableSorting: false }),
      col.accessor("id", { header: "Application ID", enableSorting: false, cell: (info) => <CopyText text={info.getValue()} /> }),
      col.accessor("session_ttl", { header: "Session lifetime", enableSorting: false }),
      col.accessor("is_active", {
        header: "Status",
        enableSorting: false,
        cell: (info) => <Badge variant="soft" color={info.getValue() ? "success" : "neutral"}>{info.getValue() ? "Enabled" : "Disabled"}</Badge>,
      }),
      col.display({
        id: "actions",
        header: "Actions",
        cell: ({ row }) => (
          <Inline gap="xs" wrap={false}>
            <ConfirmIconButton
              tooltip="Delete application"
              aria-label={`Delete ${row.original.name}`}
              icon={<IconTrash />}
              color="danger"
              title="Delete application and revoke all its sessions?"
              confirmLabel="Delete"
              onConfirm={() => removeApp(row.original.id).catch(() => undefined)}
            />
            <Tooltip content="Edit application">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label={`Edit ${row.original.name}`} onClick={() => edit(row.original)}>
                <IconEdit />
              </IconButton>
            </Tooltip>
          </Inline>
        ),
      }),
    ]);
  }, [edit, removeApp]);

  return <Stack gap="md">
    <PageHeader title="Protected Applications" actions={<Button startIcon={<IconPlus />} onClick={() => edit(null)}>Add Application</Button>} />
    {isError && <Alert color="danger" title="Unable to load protected applications" />}
    <DataTable caption="Protected applications" data={data ?? []} columns={columns} getRowId={(app) => app.id} loading={isLoading} emptyTitle="No protected applications" />
    <Drawer
      side="right"
      size="md"
      open={open}
      onOpenChange={setOpen}
      title={editing ? "Edit Protected Application" : "Add Protected Application"}
      footer={<>
        <Button variant="ghost" color="neutral" onClick={() => setOpen(false)}>Cancel</Button>
        <Button type="submit" form={formId} loading={save.isPending}>Save</Button>
      </>}
    >
      <form id={formId} onSubmit={handleSubmit(values => save.mutate(values))} noValidate>
        <Stack gap="md">
          <FormField control={control} name="name" label="Name" rules={{ required: "Name is required", validate: (v) => !!v.trim() || "Name is required", maxLength: { value: 100, message: "Name must be at most 100 characters" } }}>
            {(field) => <Input {...field} />}
          </FormField>
          <FormField control={control} name="origin" label="Application origin" description="HTTPS origin, for example https://dashboard.example.com. To change an origin, register a new application." rules={{ required: "Application origin is required", pattern: urlRule() }}>
            {(field) => <Input {...field} disabled={!!editing} />}
          </FormField>
          <FormField control={control} name="paths" label="Allowed path prefixes" description="One per line. / allows all application paths. Prefixes match complete path segments; authentication routes are reserved." rules={{ validate: (v) => !!v.trim() || "Allowed path prefixes are required" }}>
            {(field) => <Textarea {...field} rows={3} />}
          </FormField>
          <FormField control={control} name="session_ttl" label="Session lifetime" description="Duration from 1s to 24h, for example 8h. Central session expiry and revocation also apply." rules={{ required: "Session lifetime is required" }}>
            {(field) => <Input {...field} />}
          </FormField>
          <FormField control={control} name="is_active" label="Enabled" description="Disabling revokes existing application sessions. Re-enabling requires a new application login.">
            {(field) => <Switch name={field.name} ref={field.ref} onBlur={field.onBlur} checked={!!field.value} onChange={(e) => field.onChange(e.target.checked)} />}
          </FormField>
        </Stack>
      </form>
    </Drawer>
  </Stack>;
}
