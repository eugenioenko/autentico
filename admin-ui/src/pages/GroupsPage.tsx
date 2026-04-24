import { useState } from "react";
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
  Select,
} from "antd";
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  UserDeleteOutlined,
  TeamOutlined,
  ArrowLeftOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
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
import type { UserResponseExt } from "../types/user";
import type { Group, GroupMember } from "../types/group";

function GroupMembersView({
  group,
  onBack,
}: {
  group: Group;
  onBack: () => void;
}) {
  const { data: members, isLoading } = useGroupMembers(group.id);
  const { data: users } = useUsers();
  const addMember = useAddMember();
  const removeMember = useRemoveMember();
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [adding, setAdding] = useState(false);

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

  const memberUserIds = new Set((members ?? []).map((m) => m.user_id));
  const allUsers = users?.items ?? [];
  const availableUsers = allUsers.filter((u: UserResponseExt) => !memberUserIds.has(u.id));

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
    <Space direction="vertical" size="middle" style={{ display: "flex" }}>
      <Space>
        <Button icon={<ArrowLeftOutlined />} onClick={onBack}>
          Back to Groups
        </Button>
      </Space>

      <Typography.Title level={4} style={{ margin: 0 }}>
        Members of {group.name}
      </Typography.Title>

      {group.description && (
        <Typography.Text type="secondary">{group.description}</Typography.Text>
      )}

      <div>
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 8 }}>
          Add members
        </Typography.Text>
        <Space.Compact style={{ width: "100%" }}>
          <Select
            mode="multiple"
            style={{ width: "100%" }}
            placeholder="Select users to add"
            showSearch
            optionFilterProp="label"
            value={selectedUserIds}
            onChange={setSelectedUserIds}
            options={availableUsers.map((u) => ({
              value: u.id,
              label: `${u.username} (${u.email})`,
            }))}
          />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={handleAddSelected}
            loading={adding}
            disabled={selectedUserIds.length === 0}
          >
            Add
          </Button>
        </Space.Compact>
      </div>

      <Typography.Text type="secondary">
        {(members ?? []).length} member{(members ?? []).length !== 1 ? "s" : ""}
      </Typography.Text>

      <Table<GroupMember>
        columns={columns}
        dataSource={members ?? []}
        rowKey="user_id"
        loading={isLoading}
        pagination={false}
        size="small"
      />
    </Space>
  );
}

export default function GroupsPage() {
  const { data: groups, isLoading, error } = useGroups();
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

  if (membersGroup) {
    return (
      <GroupMembersView
        group={membersGroup}
        onBack={() => setMembersGroup(null)}
      />
    );
  }

  const columns: ColumnsType<Group> = [
    { title: "Name", dataIndex: "name", key: "name" },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
      ellipsis: true,
    },
    {
      title: "Created",
      dataIndex: "created_at",
      key: "created_at",
      render: (val: string) => new Date(val).toLocaleDateString(),
    },
    {
      title: "Actions",
      key: "actions",
      width: 150,
      render: (_, record) => (
        <Space>
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
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load groups" />;
  }

  return (
    <>
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <Space style={{ justifyContent: "space-between", width: "100%" }}>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Groups
          </Typography.Title>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            Create Group
          </Button>
        </Space>

        <Table<Group>
          columns={columns}
          dataSource={groups ?? []}
          rowKey="id"
          loading={isLoading}
          pagination={false}
        />
      </Space>

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
