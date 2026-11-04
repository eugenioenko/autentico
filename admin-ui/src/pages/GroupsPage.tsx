import { useEffect, useId, useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Button,
  Drawer,
  IconButton,
  Inline,
  Input,
  Stack,
  Text,
  Textarea,
  Tooltip,
  toast,
} from "@yarcl/react";
import { IconEdit, IconPlus } from "@tabler/icons-react";
import {
  useGroups,
  useCreateGroup,
  useUpdateGroup,
  useDeleteGroup,
} from "../hooks/useGroups";
import GroupClaimsDrawer from "../components/groups/GroupClaimsDrawer";
import type { ListParams } from "../api/users";
import type { Group } from "../types/group";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import { DataTable, dataColumns } from "../components/DataTable";
import { FormField } from "../components/FormField";
import SearchInput from "../components/SearchInput";
import RowActionMenu from "../components/RowActionMenu";

const NAME_PATTERN = { value: /^[a-zA-Z0-9_-]+$/, message: "Only letters, numbers, hyphens, and underscores" };
const NAME_MAX = { value: 100, message: "Max 100 characters" };


interface GroupFormValues {
  name: string;
  description: string;
}

interface GroupDrawerProps {
  mode: "create" | "edit";
  open: boolean;
  group?: Group | null;
  submitting: boolean;
  onSubmit: (values: GroupFormValues) => Promise<boolean>;
  onClose: () => void;
}

const EMPTY_GROUP: GroupFormValues = { name: "", description: "" };

function GroupDrawer({ mode, open, group, submitting, onSubmit, onClose }: GroupDrawerProps) {
  const formId = useId();
  const { control, handleSubmit, reset } = useForm<GroupFormValues>({ defaultValues: EMPTY_GROUP });
  const isCreate = mode === "create";

  useEffect(() => {
    if (open) reset(group ? { name: group.name, description: group.description ?? "" } : EMPTY_GROUP);
  }, [open, group, reset]);

  const submit = async (values: GroupFormValues) => {
    if (await onSubmit(values)) reset(EMPTY_GROUP);
  };

  return (
    <Drawer
      title={isCreate ? "Create Group" : "Edit Group"}
      side="right"
      open={open}
      onOpenChange={(next) => !next && onClose()}
      size="md"
      footer={
        <>
          <Button variant="ghost" color="neutral" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form={formId} loading={submitting}>
            {isCreate ? "Create" : "Save"}
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit(submit)} noValidate>
        <Stack gap="md">
          <FormField
            control={control}
            name="name"
            label="Name"
            description={isCreate ? undefined : "Renaming the group changes the prefix of its inherited claim names."}
            rules={{
              ...(isCreate ? { required: "Name is required" } : {}),
              pattern: NAME_PATTERN,
              maxLength: NAME_MAX,
            }}
          >
            {(field) => <Input {...field} placeholder={isCreate ? "e.g. admins" : undefined} />}
          </FormField>
          <FormField control={control} name="description" label="Description">
            {(field) => <Textarea {...field} rows={3} placeholder={isCreate ? "Optional description" : undefined} />}
          </FormField>
        </Stack>
      </form>
    </Drawer>
  );
}

/** Manages group details, membership, and group-local custom claim assignments. */
export default function GroupsPage() {
  const navigate = useNavigate();
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "name",
    order: "asc",
  });

  const { data, isLoading, error } = useGroups(listParams);
  const createGroup = useCreateGroup();
  const updateGroup = useUpdateGroup();
  const deleteGroupMutation = useDeleteGroup();

  const [claimsGroup, setClaimsGroup] = useState<Group | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editGroup, setEditGroup] = useState<Group | null>(null);

  const handleCreate = async (values: GroupFormValues) => {
    try {
      await createGroup.mutateAsync({ name: values.name, description: values.description || undefined });
      toast({ title: "Group created", color: "success" });
      setCreateOpen(false);
      return true;
    } catch {
      toast({ title: "Failed to create group", color: "danger" });
      return false;
    }
  };

  const handleUpdate = async (values: GroupFormValues) => {
    if (!editGroup) return false;
    try {
      await updateGroup.mutateAsync({ id: editGroup.id, data: values });
      toast({ title: "Group updated", color: "success" });
      setEditGroup(null);
      return true;
    } catch {
      toast({ title: "Failed to update group", color: "danger" });
      return false;
    }
  };

  const columns = useMemo(() => {
    const handleDelete = async (id: string) => {
      try {
        await deleteGroupMutation.mutateAsync(id);
        toast({ title: "Group deleted", color: "success" });
      } catch {
        toast({ title: "Failed to delete group", color: "danger" });
      }
    };
    const col = dataColumns<Group>();
    return col.columns([
      col.accessor("name", { header: "Name" }),
      col.accessor("description", {
        header: "Description",
        enableSorting: false,
        cell: (info) => <Text truncate>{info.getValue()}</Text>,
      }),
      col.accessor("member_count", { header: "Members", enableSorting: false, meta: { width: 100 } }),
      col.accessor("created_at", {
        header: "Created",
        cell: (info) => new Date(info.getValue()).toLocaleDateString(),
      }),
      col.display({
        id: "actions",
        header: "Actions",
        meta: { width: "1%" },
        cell: ({ row }) => (
          <Inline gap="xs" wrap={false}>
            <Tooltip content="Edit group">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="Edit group" onClick={() => setEditGroup(row.original)}>
                <IconEdit />
              </IconButton>
            </Tooltip>
            <RowActionMenu
              label={`More actions for ${row.original.name}`}
              actions={[
                { label: "Manage members", onSelect: () => navigate(`/groups/${encodeURIComponent(row.original.id)}/members`) },
                { label: "Manage claims", onSelect: () => setClaimsGroup(row.original) },
                {
                  label: "Delete group", danger: true, onSelect: () => handleDelete(row.original.id),
                  confirmation: { title: "Delete this group?", description: "All memberships and group claims will be removed.", confirmLabel: "Delete" },
                },
              ]}
            />
          </Inline>
        ),
      }),
    ]);
  }, [deleteGroupMutation, navigate]);

  if (error) {
    return <Alert color="danger" title="Failed to load groups" />;
  }

  return (
    <Stack gap="md">
      <DataTable
        toolbar={
          <SearchInput
            placeholder="Search groups..."
            onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
          />
        }
        actions={
          <Button startIcon={<IconPlus />} onClick={() => setCreateOpen(true)}>
            Create Group
          </Button>
        }
        caption="Groups"
        data={data?.items ?? []}
        columns={columns}
        getRowId={(g) => g.id}
        loading={isLoading}
        emptyTitle="No groups found"
        server={{
          params: listParams,
          onParamsChange: setListParams,
          total: data?.total ?? 0,
          totalLabel: (total) => `${total} groups`,
        }}
      />

      <GroupClaimsDrawer group={claimsGroup} onClose={() => setClaimsGroup(null)} />

      <GroupDrawer
        mode="create"
        open={createOpen}
        submitting={createGroup.isPending}
        onSubmit={handleCreate}
        onClose={() => setCreateOpen(false)}
      />
      <GroupDrawer
        mode="edit"
        open={!!editGroup}
        group={editGroup}
        submitting={updateGroup.isPending}
        onSubmit={handleUpdate}
        onClose={() => setEditGroup(null)}
      />
    </Stack>
  );
}
