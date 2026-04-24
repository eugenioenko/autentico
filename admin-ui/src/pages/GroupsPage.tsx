import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Button,
  Space,
  Popconfirm,
  message,
  Alert,
  Modal,
  Form,
  Input,
  AutoComplete,
  Tag,
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

function GroupMembersView({
  group,
  onBack,
}: {
  group: Group;
  onBack: () => void;
}) {
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
        `Added ${selectedUserIds.length} member${selectedUserIds.length > 1 ? "s" : ""}`
      );
      setSelectedUserIds([]);
    } catch {
      message.error("Failed to add members");
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (userId: string) => {
    try {
      await removeMember.mutateAsync({ groupId: group.id, userId });
      message.success("Member removed");
    } catch {
      message.error("Failed to remove member");
    }
  };

  const selectedUsers = selectedUserIds.map((id) => {
    const user = usersData?.items?.find((u) => u.id === id);
    return { id, label: user ? user.username : id };
  });

  const columns: ColumnsType<GroupMember> = [
    { title: "Username", dataIndex: "username", key: "username" },
    { title: "Email", dataIndex: "email", key: "email" },
    {
      title: "Added",
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
          title="Remove this member?"
          onConfirm={() => handleRemove(record.user_id)}
          okText="Remove"
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
            Back to Groups
          </Button>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Members of {group.name}
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
          Add members
        </Typography.Text>
        <Space.Compact style={{ maxWidth: 480 }}>
          <AutoComplete
            style={{ width: 320 }}
            placeholder="Search users to add"
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
            Add{selectedUserIds.length > 0 ? ` (${selectedUserIds.length})` : ""}
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
      message.success("Group created");
      setCreateOpen(false);
      createForm.resetFields();
    } catch {
      message.error("Failed to create group");
    }
  };

  const handleUpdate = async (values: { name?: string; description?: string }) => {
    if (!editGroup) return;
    try {
      await updateGroup.mutateAsync({ id: editGroup.id, data: values });
      message.success("Group updated");
      setEditGroup(null);
      editForm.resetFields();
    } catch {
      message.error("Failed to update group");
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteGroupMutation.mutateAsync(id);
      message.success("Group deleted");
    } catch {
      message.error("Failed to delete group");
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
      title: "Name",
      dataIndex: "name",
      key: "name",
      sorter: true,
    },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
      ellipsis: true,
    },
    {
      title: "Members",
      dataIndex: "member_count",
      key: "member_count",
      width: 100,
    },
    {
      title: "Created",
      dataIndex: "created_at",
      key: "created_at",
      sorter: true,
      render: (val: string) => new Date(val).toLocaleDateString(),
    },
    {
      title: "Actions",
      key: "actions",
      width: 120,
      render: (_, record) => (
        <Space>
          <Popconfirm
            title="Delete this group?"
            description="All memberships will be removed."
            onConfirm={() => handleDelete(record.id)}
            okText="Delete"
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
    return <Alert type="error" message="Failed to load groups" />;
  }

  return (
    <>
      <Space style={{ justifyContent: "space-between", width: "100%", flexShrink: 0 }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          Groups
        </Typography.Title>
        <Space>
          <Input.Search
            placeholder="Search groups..."
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
            Create Group
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
            showTotal: (total) => `${total} groups`,
          }}
        />
      </div>

      {/* Create Modal */}
      <Modal
        title="Create Group"
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
            label="Name"
            rules={[
              { required: true, message: "Name is required" },
              {
                pattern: /^[a-zA-Z0-9_-]+$/,
                message: "Only letters, numbers, hyphens, and underscores",
              },
              { max: 100, message: "Max 100 characters" },
            ]}
          >
            <Input placeholder="e.g. admins" />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input.TextArea rows={3} placeholder="Optional description" />
          </Form.Item>
        </Form>
      </Modal>

      {/* Edit Modal */}
      <Modal
        title="Edit Group"
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
            label="Name"
            rules={[
              {
                pattern: /^[a-zA-Z0-9_-]+$/,
                message: "Only letters, numbers, hyphens, and underscores",
              },
              { max: 100, message: "Max 100 characters" },
            ]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input.TextArea rows={3} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
