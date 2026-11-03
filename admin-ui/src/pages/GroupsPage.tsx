import { useEffect, useId, useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import {
  Alert,
  Button,
  Combobox,
  Dialog,
  Field,
  IconButton,
  Inline,
  Input,
  Stack,
  Text,
  Textarea,
  Tooltip,
  toast,
} from "@yarcl/react";
import { IconArrowLeft, IconEdit, IconId, IconPlus, IconTrash, IconUserMinus, IconUsersGroup } from "@tabler/icons-react";
import {
  useGroups,
  useCreateGroup,
  useUpdateGroup,
  useDeleteGroup,
  useGroupMembers,
  useAddMember,
  useRemoveMember,
} from "../hooks/useGroups";
import GroupClaimsDrawer from "../components/groups/GroupClaimsDrawer";
import { useUsers } from "../hooks/useUsers";
import type { ListParams } from "../api/users";
import type { Group, GroupMember } from "../types/group";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import { DataTable, dataColumns } from "../components/DataTable";
import { FormField } from "../components/FormField";
import PageHeader from "../components/PageHeader";
import SearchInput from "../components/SearchInput";
import ConfirmIconButton from "../components/ConfirmIconButton";

const NAME_PATTERN = { value: /^[a-zA-Z0-9_-]+$/, message: "Only letters, numbers, hyphens, and underscores" };
const NAME_MAX = { value: 100, message: "Max 100 characters" };

function GroupMembersView({ group, onBack }: { group: Group; onBack: () => void }) {
  const { data: members, isLoading } = useGroupMembers(group.id);
  const addMember = useAddMember();
  const removeMember = useRemoveMember();
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [adding, setAdding] = useState(false);
  const [userSearchParams, setUserSearchParams] = useState<ListParams>({ limit: 20, offset: 0 });
  const { data: usersData, isFetching: usersLoading } = useUsers(userSearchParams);

  const memberUserIds = new Set((members ?? []).map((m) => m.user_id));
  const userOptions = (usersData?.items ?? [])
    .filter((u) => !memberUserIds.has(u.id))
    .map((u) => ({ value: u.id, label: `${u.username} (${u.email})` }));

  const handleUserSearch = (value: string) => {
    setUserSearchParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }));
  };

  const handleAddSelected = async () => {
    if (selectedUserIds.length === 0) return;
    setAdding(true);
    try {
      await Promise.all(selectedUserIds.map((userId) => addMember.mutateAsync({ groupId: group.id, userId })));
      toast({
        title: `Added ${selectedUserIds.length} member${selectedUserIds.length > 1 ? "s" : ""}`,
        color: "success",
      });
      setSelectedUserIds([]);
    } catch {
      toast({ title: "Failed to add members", color: "danger" });
    } finally {
      setAdding(false);
    }
  };

  const columns = useMemo(() => {
    const handleRemove = async (userId: string) => {
      try {
        await removeMember.mutateAsync({ groupId: group.id, userId });
        toast({ title: "Member removed", color: "success" });
      } catch {
        toast({ title: "Failed to remove member", color: "danger" });
      }
    };
    const col = dataColumns<GroupMember>();
    return col.columns([
      col.accessor("username", { header: "Username" }),
      col.accessor("email", { header: "Email" }),
      col.accessor("created_at", {
        header: "Added",
        cell: (info) => new Date(info.getValue()).toLocaleDateString(),
      }),
      col.display({
        id: "actions",
        header: "",
        meta: { align: "end", width: 50 },
        cell: ({ row }) => (
          <ConfirmIconButton
            tooltip="Remove member"
            aria-label="Remove member"
            icon={<IconUserMinus />}
            color="danger"
            title="Remove this member?"
            confirmLabel="Remove"
            onConfirm={() => handleRemove(row.original.user_id)}
          />
        ),
      }),
    ]);
  }, [group.id, removeMember]);

  return (
    <Stack gap="md">
      <Inline>
        <Button variant="ghost" color="neutral" startIcon={<IconArrowLeft />} onClick={onBack}>
          Back to Groups
        </Button>
      </Inline>
      <PageHeader title={`Members of ${group.name}`} description={group.description || undefined} />

      <Inline gap="xs" wrap={false} align="end">
        <Field label="Add members">
          <Combobox
            multiple
            filter={false}
            placeholder="Search users to add"
            options={userOptions}
            loading={usersLoading}
            value={selectedUserIds}
            onValueChange={setSelectedUserIds}
            onInputValueChange={handleUserSearch}
          />
        </Field>
        <Button startIcon={<IconPlus />} onClick={handleAddSelected} loading={adding} disabled={selectedUserIds.length === 0}>
          Add{selectedUserIds.length > 0 ? ` (${selectedUserIds.length})` : ""}
        </Button>
      </Inline>

      <DataTable
        caption={`Members of ${group.name}`}
        data={members ?? []}
        columns={columns}
        getRowId={(m) => m.user_id}
        loading={isLoading}
        pageSize={false}
        emptyTitle="No members"
      />
    </Stack>
  );
}

interface GroupFormValues {
  name: string;
  description: string;
}

interface GroupDialogProps {
  mode: "create" | "edit";
  open: boolean;
  group?: Group | null;
  submitting: boolean;
  onSubmit: (values: GroupFormValues) => Promise<boolean>;
  onClose: () => void;
}

const EMPTY_GROUP: GroupFormValues = { name: "", description: "" };

function GroupDialog({ mode, open, group, submitting, onSubmit, onClose }: GroupDialogProps) {
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
    <Dialog
      title={isCreate ? "Create Group" : "Edit Group"}
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
    </Dialog>
  );
}

/** Manages group details, membership, and group-local custom claim assignments. */
export default function GroupsPage() {
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
  const [membersGroup, setMembersGroup] = useState<Group | null>(null);

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
        meta: { width: 160 },
        cell: ({ row }) => (
          <Inline gap="xs" wrap={false}>
            <ConfirmIconButton
              tooltip="Delete group"
              aria-label="Delete group"
              icon={<IconTrash />}
              color="danger"
              title="Delete this group?"
              description="All memberships and group claims will be removed."
              confirmLabel="Delete"
              onConfirm={() => handleDelete(row.original.id)}
            />
            <Tooltip content="Manage members">
              <IconButton
                variant="ghost"
                color="neutral"
                size="sm"
                aria-label="Manage group members"
                onClick={() => setMembersGroup(row.original)}
              >
                <IconUsersGroup />
              </IconButton>
            </Tooltip>
            <Tooltip content="Manage claims">
              <IconButton
                variant="ghost"
                color="neutral"
                size="sm"
                aria-label="Manage group claims"
                onClick={() => setClaimsGroup(row.original)}
              >
                <IconId />
              </IconButton>
            </Tooltip>
            <Tooltip content="Edit group">
              <IconButton variant="ghost" color="neutral" size="sm" aria-label="Edit group" onClick={() => setEditGroup(row.original)}>
                <IconEdit />
              </IconButton>
            </Tooltip>
          </Inline>
        ),
      }),
    ]);
  }, [deleteGroupMutation]);

  if (membersGroup) {
    return <GroupMembersView group={membersGroup} onBack={() => setMembersGroup(null)} />;
  }

  if (error) {
    return <Alert color="danger" title="Failed to load groups" />;
  }

  return (
    <Stack gap="md">
      <PageHeader
        title="Groups"
        actions={
          <>
            <SearchInput
              placeholder="Search groups..."
              onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
            />
            <Button startIcon={<IconPlus />} onClick={() => setCreateOpen(true)}>
              Create Group
            </Button>
          </>
        }
      />

      <DataTable
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

      <GroupDialog
        mode="create"
        open={createOpen}
        submitting={createGroup.isPending}
        onSubmit={handleCreate}
        onClose={() => setCreateOpen(false)}
      />
      <GroupDialog
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
