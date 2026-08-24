import { useState } from "react";
import { Drawer, Select, Table, Button, Space, Typography, Popconfirm, App } from "antd";
import { UserDeleteOutlined, PlusOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useGroups, useAddMember, useRemoveMember } from "../../hooks/useGroups";
import { getUserGroups } from "../../api/groups";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Group } from "../../types/group";
import { useTranslation } from "react-i18next";

interface UserGroupsDrawerProps {
  open: boolean;
  userId: string | null;
  username: string;
  onClose: () => void;
}

export default function UserGroupsDrawer({ open, userId, username, onClose }: UserGroupsDrawerProps) {
  const { t } = useTranslation();
  const { message } = App.useApp();
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
      message.success(t("users.addedToGroups", { count: selectedGroupIds.length }));
      setSelectedGroupIds([]);
    } catch {
      message.error(t("users.addGroupsFailed"));
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (groupId: string) => {
    if (!userId) return;
    try {
      await removeMember.mutateAsync({ groupId, userId });
      queryClient.invalidateQueries({ queryKey: ["user-groups", userId] });
      message.success(t("users.groupRemoved"));
    } catch {
      message.error(t("users.removeGroupFailed"));
    }
  };

  const memberGroupIds = new Set((userGroups ?? []).map((g) => g.id));
  const availableGroups = (allGroups?.items ?? []).filter((g) => !memberGroupIds.has(g.id));

  const columns: ColumnsType<Group> = [
    { title: t("common.name"), dataIndex: "name", key: "name" },
    { title: t("common.description"), dataIndex: "description", key: "description", ellipsis: true },
    {
      title: "",
      key: "actions",
      width: 50,
      render: (_, record) => (
        <Popconfirm
          title={t("users.removeFromGroup")}
          onConfirm={() => handleRemove(record.id)}
          okText={t("users.removeAction")}
          okButtonProps={{ danger: true }}
        >
          <Button type="text" size="small" danger icon={<UserDeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <Drawer
      title={t("users.groupsOf", { username })}
      open={open}
      onClose={() => { onClose(); setSelectedGroupIds([]); }}
      width={480}
    >
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <div>
          <Typography.Text type="secondary" style={{ display: "block", marginBottom: 8 }}>
            {t("users.addToGroups")}
          </Typography.Text>
          <Space.Compact style={{ width: "100%" }}>
            <Select
              mode="multiple"
              style={{ width: "100%" }}
              placeholder={t("users.selectGroupsToAdd")}
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
              {t("common.add")}
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
          locale={{ emptyText: t("users.notMemberOfAnyGroup") }}
        />
      </Space>
    </Drawer>
  );
}
