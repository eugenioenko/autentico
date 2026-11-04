import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Alert, Button, Combobox, Field, Inline, Spinner, Stack, Text, toast } from "@yarcl/react";
import { IconArrowLeft, IconPlus, IconUserMinus } from "@tabler/icons-react";
import { useGroup, useGroupMembers, useAddMember, useRemoveMember } from "../hooks/useGroups";
import { useUsers } from "../hooks/useUsers";
import type { ListParams } from "../api/users";
import type { Group, GroupMember } from "../types/group";
import { DataTable, dataColumns } from "../components/DataTable";
import ConfirmIconButton from "../components/ConfirmIconButton";

export default function GroupMembersPage() {
  const { groupId = "" } = useParams();
  const navigate = useNavigate();
  const { data: group, isLoading, error } = useGroup(groupId);
  if (isLoading) return <div className="page-loading"><Spinner label="Loading group" /></div>;
  if (error || !group) return <Alert color="danger" title="Group not found or unavailable" />;
  return <GroupMembersView key={group.id} group={group} onBack={() => navigate("/groups")} />;
}

function GroupMembersView({ group, onBack }: { group: Group; onBack: () => void }) {
  const { data: members, isLoading, error } = useGroupMembers(group.id);
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

  if (error) return <Alert color="danger" title="Failed to load group members" />;

  return (
    <Stack gap="md">
      <Inline gap="md" align="center">
        <Button className="admin-back-button" variant="ghost" color="neutral" startIcon={<IconArrowLeft />} onClick={onBack}>
          Back to Groups
        </Button>
        {group.description && <Text muted>{group.description}</Text>}
      </Inline>

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
