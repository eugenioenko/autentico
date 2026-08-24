import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Button,
  Space,
  Popconfirm,
  Alert,
  Modal,
  Form,
  Input,
  AutoComplete,
  Tag,
  App,
} from "antd";
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  UserDeleteOutlined,
  TeamOutlined,
  ArrowLeftOutlined,
} from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { SorterResult } from "antd/es/table/interface";
import {
  useGroups,
  useCreateGroup,
  useUpdateGroup,
  useDeleteGroup,
  useGroupMembers,
  useAddMember,
  useRemoveMember,
} from "../hooks/useGroups";
import { useUsers } from "../hooks/useUsers";
import type { ListParams } from "../api/users";
import type { Group, GroupMember } from "../types/group";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";
import { useTranslation } from "react-i18next";

function GroupMembersView({
  group,
  onBack,
}: {
  group: Group;
  onBack: () => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const { data: members, isLoading } = useGroupMembers(group.id);
  const addMember = useAddMember();
  const removeMember = useRemoveMember();
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [adding, setAdding] = useState(false);
  const [userSearch, setUserSearch] = useState("");
  const [userSearchParams, setUserSearchParams] = useState<ListParams>({
    limit: 20,
    offset: 0,
  });
  const { data: usersData } = useUsers(userSearchParams);

  const memberUserIds = new Set((members ?? []).map((m) => m.user_id));
  const userOptions = (usersData?.items ?? [])
    .filter((u) => !memberUserIds.has(u.id) && !selectedUserIds.includes(u.id))
    .map((u) => ({
      value: u.id,
      label: `${u.username} (${u.email})`,
    }));

  const handleUserSearch = (value: string) => {
    setUserSearch(value);
    setUserSearchParams((prev) => ({
      ...prev,
      search: value || undefined,
      offset: 0,
    }));
  };

  const handleSelectUser = (userId: string) => {
    if (!selectedUserIds.includes(userId)) {
      setSelectedUserIds((prev) => [...prev, userId]);
    }
    setUserSearch("");
  };

  const handleAddSelected = async () => {
    if (selectedUserIds.length === 0) return;
    setAdding(true);
    try {
      await Promise.all(
        selectedUserIds.map((userId) =>
          addMember.mutateAsync({ groupId: group.id, userId })
        )
      );
      message.success(
        t("groups.addedCount", { count: selectedUserIds.length })
      );
      setSelectedUserIds([]);
    } catch {
      message.error(t("groups.addMembersFailed"));
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (userId: string) => {
    try {
      await removeMember.mutateAsync({ groupId: group.id, userId });
      message.success(t("groups.memberRemoved"));
    } catch {
      message.error(t("groups.removeMemberFailed"));
    }
  };

  const selectedUsers = selectedUserIds.map((id) => {
    const user = usersData?.items?.find((u) => u.id === id);
    return { id, label: user ? user.username : id };
  });

  const columns: ColumnsType<GroupMember> = [
    { title: t("users.username"), dataIndex: "username", key: "username" },
    { title: t("users.email"), dataIndex: "email", key: "email" },
    {
      title: t("groups.addedAt"),
      dataIndex: "created_at",
      key: "created_at",
      render: (val: string) => new Date(val).toLocaleDateString(),
    },
    {
      title: "",
      key: "actions",
      width: 50,
      render: (_, record) => (
        <Popconfirm
          title={t("groups.removeMemberConfirm")}
          onConfirm={() => handleRemove(record.user_id)}
          okText={t("groups.removeAction")}
          okButtonProps={{ danger: true }}
        >
          <Button
            type="text"
            size="small"
            danger
            icon={<UserDeleteOutlined />}
          />
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      <Space style={{ justifyContent: "space-between", width: "100%", flexShrink: 0 }}>
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={onBack}>
            {t("groups.backToGroupList")}
          </Button>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("groups.membersOf", { group: group.name })}
          </Typography.Title>
        </Space>
      </Space>

      {group.description && (
        <Typography.Text type="secondary" style={{ display: "block", marginTop: 8, flexShrink: 0 }}>
          {group.description}
        </Typography.Text>
      )}

      <div style={{ marginTop: 12, flexShrink: 0 }}>
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 8 }}>
          {t("groups.addMembers")}
        </Typography.Text>
        <Space.Compact style={{ maxWidth: 480 }}>
          <AutoComplete
            style={{ width: 320 }}
            placeholder={t("groups.searchUsersToAdd")}
            options={userOptions}
            value={userSearch}
            onSearch={handleUserSearch}
            onSelect={handleSelectUser}
            allowClear
          />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={handleAddSelected}
            loading={adding}
            disabled={selectedUserIds.length === 0}
          >
            {t("common.add")}{selectedUserIds.length > 0 ? ` (${selectedUserIds.length})` : ""}
          </Button>
        </Space.Compact>
        {selectedUsers.length > 0 && (
          <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 4, alignItems: "center" }}>
            {selectedUsers.map((u) => (
              <Tag
                key={u.id}
                closable
                onClose={() => setSelectedUserIds((prev) => prev.filter((id) => id !== u.id))}
              >
                {u.label}
              </Tag>
            ))}
          </div>
        )}
      </div>

      <div ref={tableContainerRef} style={{ flex: 1, overflow: "hidden", marginTop: 16 }}>
        <Table<GroupMember>
          columns={columns}
          dataSource={members ?? []}
          rowKey="user_id"
          loading={isLoading}
          scroll={scrollY ? { y: scrollY } : undefined}
          pagination={false}
          size="small"
        />
      </div>
    </>
  );
}

export default function GroupsPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "name",
    order: "asc",
  });
  const [searchValue, setSearchValue] = useState("");

  const { data, isLoading, error } = useGroups(listParams);
  const createGroup = useCreateGroup();
  const updateGroup = useUpdateGroup();
  const deleteGroupMutation = useDeleteGroup();

  const [createOpen, setCreateOpen] = useState(false);
  const [editGroup, setEditGroup] = useState<Group | null>(null);
  const [membersGroup, setMembersGroup] = useState<Group | null>(null);

  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();

  const handleCreate = async (values: { name: string; description?: string }) => {
    try {
      await createGroup.mutateAsync(values);
      message.success(t("groups.groupCreated"));
      setCreateOpen(false);
      createForm.resetFields();
    } catch {
      message.error(t("groups.createGroupFailed"));
    }
  };

  const handleUpdate = async (values: { name?: string; description?: string }) => {
    if (!editGroup) return;
    try {
      await updateGroup.mutateAsync({ id: editGroup.id, data: values });
      message.success(t("groups.groupUpdated"));
      setEditGroup(null);
      editForm.resetFields();
    } catch {
      message.error(t("groups.updateGroupFailed"));
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteGroupMutation.mutateAsync(id);
      message.success(t("groups.groupDeleted"));
    } catch {
      message.error(t("groups.deleteGroupFailed"));
    }
  };

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter: SorterResult<Group> | SorterResult<Group>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      setListParams((prev) => ({
        ...prev,
        offset: ((pagination.current ?? 1) - 1) * (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : "name",
        order: s.order === "descend" ? "desc" : "asc",
      }));
    },
    []
  );

  const handleSearch = useCallback((value: string) => {
    setListParams((prev) => ({
      ...prev,
      search: value || undefined,
      offset: 0,
    }));
  }, []);

  if (membersGroup) {
    return (
      <GroupMembersView
        group={membersGroup}
        onBack={() => setMembersGroup(null)}
      />
    );
  }

  const columns: ColumnsType<Group> = [
    {
      title: t("common.name"),
      dataIndex: "name",
      key: "name",
      sorter: true,
    },
    {
      title: t("common.description"),
      dataIndex: "description",
      key: "description",
      ellipsis: true,
    },
    {
      title: t("groups.memberCount"),
      dataIndex: "member_count",
      key: "member_count",
      width: 100,
    },
    {
      title: t("common.created"),
      dataIndex: "created_at",
      key: "created_at",
      sorter: true,
      render: (val: string) => new Date(val).toLocaleDateString(),
    },
    {
      title: t("common.actions"),
      key: "actions",
      width: 120,
      render: (_, record) => (
        <Space>
          <Popconfirm
            title={t("groups.deleteGroupConfirm")}
            description={t("groups.deleteGroupDesc")}
            onConfirm={() => handleDelete(record.id)}
            okText={t("common.delete")}
            okButtonProps={{ danger: true }}
          >
            <Button
              type="text"
              size="small"
              danger
              icon={<DeleteOutlined />}
            />
          </Popconfirm>
          <Button
            type="text"
            size="small"
            icon={<TeamOutlined />}
            onClick={() => setMembersGroup(record)}
          />
          <Button
            type="text"
            size="small"
            icon={<EditOutlined />}
            onClick={() => {
              setEditGroup(record);
              editForm.setFieldsValue({
                name: record.name,
                description: record.description,
              });
            }}
          />
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message={t("groups.failedToLoadGroups")} />;
  }

  return (
    <>
      <Space style={{ justifyContent: "space-between", width: "100%", flexShrink: 0 }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("groups.title")}
        </Typography.Title>
        <Space>
          <Input.Search
            placeholder={t("groups.searchGroups")}
            allowClear
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onSearch={handleSearch}
            style={{ width: 250 }}
          />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            {t("groups.createGroup")}
          </Button>
        </Space>
      </Space>

      <div ref={tableContainerRef} style={{ flex: 1, overflow: "hidden", marginTop: 16 }}>
        <Table<Group>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey="id"
          loading={isLoading}
          onChange={handleTableChange}
          scroll={scrollY ? { y: scrollY } : undefined}
          pagination={{
            current: Math.floor((listParams.offset ?? 0) / (listParams.limit ?? DEFAULT_PAGE_SIZE)) + 1,
            pageSize: listParams.limit ?? DEFAULT_PAGE_SIZE,
            total: data?.total ?? 0,
            showSizeChanger: true,
            pageSizeOptions: PAGE_SIZE_OPTIONS,
            showTotal: (total) => t("groups.totalGroups", { total }),
          }}
        />
      </div>

      <Modal
        title={t("groups.createGroupTitle")}
        open={createOpen}
        onCancel={() => {
          setCreateOpen(false);
          createForm.resetFields();
        }}
        onOk={() => createForm.submit()}
        confirmLoading={createGroup.isPending}
      >
        <Form form={createForm} layout="vertical" onFinish={handleCreate}>
          <Form.Item
            name="name"
            label={t("common.name")}
            rules={[
              { required: true, message: t("groups.groupNameRequired") },
              {
                pattern: /^[a-zA-Z0-9_-]+$/,
                message: t("groups.groupNamePattern"),
              },
              { max: 100, message: t("groups.groupNameMax") },
            ]}
          >
            <Input placeholder={t("groups.groupNamePlaceholder")} />
          </Form.Item>
          <Form.Item name="description" label={t("common.description")}>
            <Input.TextArea rows={3} placeholder={t("groups.optionalDescription")} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t("groups.editGroupTitle")}
        open={!!editGroup}
        onCancel={() => {
          setEditGroup(null);
          editForm.resetFields();
        }}
        onOk={() => editForm.submit()}
        confirmLoading={updateGroup.isPending}
      >
        <Form form={editForm} layout="vertical" onFinish={handleUpdate}>
          <Form.Item
            name="name"
            label={t("common.name")}
            rules={[
              {
                pattern: /^[a-zA-Z0-9_-]+$/,
                message: t("groups.groupNamePattern"),
              },
              { max: 100, message: t("groups.groupNameMax") },
            ]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="description" label={t("common.description")}>
            <Input.TextArea rows={3} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
