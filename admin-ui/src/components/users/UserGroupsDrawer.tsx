import { useState } from "react";
import { Drawer, Select, Table, Button, Space, Typography, Popconfirm, message } from "antd";
import { UserDeleteOutlined, PlusOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useGroups, useAddMember, useRemoveMember } from "../../hooks/useGroups";
import { getUserGroups } from "../../api/groups";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Group } from "../../types/group";

interface UserGroupsDrawerProps {
  open: boolean;
  userId: string | null;
  username: string;
  onClose: () => void;
}

export default function UserGroupsDrawer({ open, userId, username, onClose }: UserGroupsDrawerProps) {
  const { data: allGroups } = useGroups();
  const addMember = useAddMember();
  const removeMember = useRemoveMember();
  const queryClient = useQueryClient();
  const [selectedGroupIds, setSelectedGroupIds] = useState<string[]>([]);
  const [adding, setAdding] = useState(false);

  const { data: userGroups, isLoading } = useQuery({
    queryKey: ["user-groups", userId],
    queryFn: () => getUserGroups(userId!),
    enabled: !!userId && open,
  });

  const handleAddSelected = async () => {
    if (!userId || selectedGroupIds.length === 0) return;
    setAdding(true);
    try {
      await Promise.all(
        selectedGroupIds.map((groupId) => addMember.mutateAsync({ groupId, userId }))
      );
      queryClient.invalidateQueries({ queryKey: ["user-groups", userId] });
      message.success(`Added to ${selectedGroupIds.length} group${selectedGroupIds.length > 1 ? "s" : ""}`);
      setSelectedGroupIds([]);
    } catch {
      message.error("Failed to add groups");
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (groupId: string) => {
    if (!userId) return;
    try {
      await removeMember.mutateAsync({ groupId, userId });
      queryClient.invalidateQueries({ queryKey: ["user-groups", userId] });
      message.success("Group removed");
    } catch {
      message.error("Failed to remove group");
    }
  };

  const memberGroupIds = new Set((userGroups ?? []).map((g) => g.id));
  const availableGroups = (allGroups?.items ?? []).filter((g) => !memberGroupIds.has(g.id));

  const columns: ColumnsType<Group> = [
    { title: "Name", dataIndex: "name", key: "name" },
    { title: "Description", dataIndex: "description", key: "description", ellipsis: true },
    {
      title: "",
      key: "actions",
      width: 50,
      render: (_, record) => (
        <Popconfirm
          title="Remove from this group?"
          onConfirm={() => handleRemove(record.id)}
          okText="Remove"
          okButtonProps={{ danger: true }}
        >
          <Button type="text" size="small" danger icon={<UserDeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <Drawer
      title={`Groups for ${username}`}
      open={open}
      onClose={() => { onClose(); setSelectedGroupIds([]); }}
      width={480}
    >
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <div>
          <Typography.Text type="secondary" style={{ display: "block", marginBottom: 8 }}>
            Add to groups
          </Typography.Text>
          <Space.Compact style={{ width: "100%" }}>
            <Select
              mode="multiple"
              style={{ width: "100%" }}
              placeholder="Select groups to add"
              showSearch
              optionFilterProp="label"
              value={selectedGroupIds}
              onChange={setSelectedGroupIds}
              options={availableGroups.map((g) => ({
                value: g.id,
                label: g.name,
              }))}
            />
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleAddSelected}
              loading={adding}
              disabled={selectedGroupIds.length === 0}
            >
              Add
            </Button>
          </Space.Compact>
        </div>

        <Table<Group>
          columns={columns}
          dataSource={userGroups ?? []}
          rowKey="id"
          loading={isLoading}
          pagination={false}
          size="small"
          locale={{ emptyText: "Not a member of any group" }}
        />
      </Space>
    </Drawer>
  );
}
