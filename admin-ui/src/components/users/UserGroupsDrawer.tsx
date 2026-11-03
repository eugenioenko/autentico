import { useMemo, useState } from "react";
import { Button, Combobox, Drawer, Inline, Stack, Text, VisuallyHidden, toast } from "@yarcl/react";
import { IconPlus, IconUserMinus } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useGroups, useAddMember, useRemoveMember } from "../../hooks/useGroups";
import { getUserGroups } from "../../api/groups";
import type { Group } from "../../types/group";
import { DataTable, dataColumns } from "../DataTable";
import ConfirmIconButton from "../ConfirmIconButton";
import "./UserGroupsDrawer.css";

interface UserGroupsDrawerProps {
  open: boolean;
  userId: string | null;
  username: string;
  onClose: () => void;
}

export default function UserGroupsDrawer({ open, userId, username, onClose }: UserGroupsDrawerProps) {
  const { data: allGroups } = useGroups();
  const addMember = useAddMember();
  const { mutateAsync: removeMember } = useRemoveMember();
  const queryClient = useQueryClient();
  const [selectedGroupIds, setSelectedGroupIds] = useState<string[]>([]);
  const [adding, setAdding] = useState(false);

  const { data: userGroups, isLoading } = useQuery({
    queryKey: ["user-groups", userId],
    queryFn: () => getUserGroups(userId!),
    enabled: !!userId && open,
  });

  const handleClose = () => {
    onClose();
    setSelectedGroupIds([]);
  };

  const handleAddSelected = async () => {
    if (!userId || selectedGroupIds.length === 0) return;
    setAdding(true);
    try {
      await Promise.all(selectedGroupIds.map((groupId) => addMember.mutateAsync({ groupId, userId })));
      queryClient.invalidateQueries({ queryKey: ["user-groups", userId] });
      toast({
        title: `Added to ${selectedGroupIds.length} group${selectedGroupIds.length > 1 ? "s" : ""}`,
        color: "success",
      });
      setSelectedGroupIds([]);
    } catch {
      toast({ title: "Failed to add groups", color: "danger" });
    } finally {
      setAdding(false);
    }
  };

  const memberGroupIds = new Set((userGroups ?? []).map((g) => g.id));
  const availableGroups = (allGroups?.items ?? []).filter((g) => !memberGroupIds.has(g.id));

  const columns = useMemo(() => {
    const handleRemove = async (groupId: string) => {
      if (!userId) return;
      try {
        await removeMember({ groupId, userId });
        queryClient.invalidateQueries({ queryKey: ["user-groups", userId] });
        toast({ title: "Group removed", color: "success" });
      } catch {
        toast({ title: "Failed to remove group", color: "danger" });
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
      col.display({
        id: "actions",
        header: () => <VisuallyHidden>Actions</VisuallyHidden>,
        meta: { width: 50 },
        cell: ({ row }) => (
          <ConfirmIconButton
            tooltip="Remove from group"
            aria-label="Remove from group"
            color="danger"
            icon={<IconUserMinus />}
            title="Remove from this group?"
            confirmLabel="Remove"
            onConfirm={() => handleRemove(row.original.id)}
          />
        ),
      }),
    ]);
  }, [userId, removeMember, queryClient]);

  return (
    <Drawer title={`Groups for ${username}`} open={open} onOpenChange={(next) => !next && handleClose()} side="right" size="md">
      <Stack gap="md">
        <Stack gap="xs">
          <Text muted>Add to groups</Text>
          <Inline gap="xs" wrap={false} align="start">
            <Combobox
              multiple
              className="user-groups-picker"
              aria-label="Add to groups"
              placeholder="Select groups to add"
              value={selectedGroupIds}
              onValueChange={setSelectedGroupIds}
              options={availableGroups.map((g) => ({ value: g.id, label: g.name }))}
            />
            <Button startIcon={<IconPlus />} onClick={handleAddSelected} loading={adding} disabled={selectedGroupIds.length === 0}>
              Add
            </Button>
          </Inline>
        </Stack>

        <DataTable
          caption={`Groups for ${username}`}
          data={userGroups ?? []}
          columns={columns}
          getRowId={(g) => g.id}
          loading={isLoading}
          pageSize={false}
          emptyTitle="Not a member of any group"
        />
      </Stack>
    </Drawer>
  );
}
