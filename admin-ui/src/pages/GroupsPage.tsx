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
  UserAddOutlined,
  UserDeleteOutlined,
  TeamOutlined,
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
import type { Group, GroupMember } from "../types/group";

export default function GroupsPage() {
  const { data: groups, isLoading, error } = useGroups();
  const createGroup = useCreateGroup();
  const updateGroup = useUpdateGroup();
  const deleteGroupMutation = useDeleteGroup();
  const addMember = useAddMember();
  const removeMember = useRemoveMember();

  const [createOpen, setCreateOpen] = useState(false);
  const [editGroup, setEditGroup] = useState<Group | null>(null);
  const [membersGroup, setMembersGroup] = useState<Group | null>(null);
  const [addMemberOpen, setAddMemberOpen] = useState(false);

  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();

  const { data: members, isLoading: membersLoading } = useGroupMembers(
    membersGroup?.id ?? null
  );
  const { data: users } = useUsers();

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

  const handleAddMember = async (userId: string) => {
    if (!membersGroup) return;
    try {
      await addMember.mutateAsync({ groupId: membersGroup.id, userId });
      message.success("Member added");
      setAddMemberOpen(false);
    } catch {
      message.error("Failed to add member");
    }
  };

  const handleRemoveMember = async (userId: string) => {
    if (!membersGroup) return;
    try {
      await removeMember.mutateAsync({ groupId: membersGroup.id, userId });
      message.success("Member removed");
    } catch {
      message.error("Failed to remove member");
    }
  };

  const columns: ColumnsType<Group> = [
    { title: "Name", dataIndex: "name", key: "name" },
    { title: "Description", dataIndex: "description", key: "description", ellipsis: true },
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
            onClick={() => {
              setMembersGroup(record);
            }}
          />
          <Button
            type="text"
            size="small"
            icon={<EditOutlined />}
            onClick={() => {
              setEditGroup(record);
              editForm.setFieldsValue({ name: record.name, description: record.description });
            }}
          />
          <Popconfirm
            title="Delete this group?"
            description="All memberships will be removed."
            onConfirm={() => handleDelete(record.id)}
            okText="Delete"
            okButtonProps={{ danger: true }}
          >
            <Button type="text" size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const memberColumns: ColumnsType<GroupMember> = [
    { title: "Username", dataIndex: "username", key: "username" },
    { title: "Email", dataIndex: "email", key: "email" },
    {
      title: "Added",
      dataIndex: "created_at",
      key: "created_at",
      render: (val: string) => new Date(val).toLocaleDateString(),
    },
    {
      title: "Actions",
      key: "actions",
      width: 80,
      render: (_, record) => (
        <Popconfirm
          title="Remove this member?"
          onConfirm={() => handleRemoveMember(record.user_id)}
          okText="Remove"
          okButtonProps={{ danger: true }}
        >
          <Button type="text" size="small" danger icon={<UserDeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  // Users not already in the group
  const availableUsers = (users ?? []).filter(
    (u) => !(members ?? []).some((m) => m.user_id === u.id)
  );

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
        onCancel={() => { setCreateOpen(false); createForm.resetFields(); }}
        onOk={() => createForm.submit()}
        confirmLoading={createGroup.isPending}
      >
        <Form form={createForm} layout="vertical" onFinish={handleCreate}>
          <Form.Item
            name="name"
            label="Name"
            rules={[
              { required: true, message: "Name is required" },
              { pattern: /^[a-zA-Z0-9_-]+$/, message: "Only letters, numbers, hyphens, and underscores" },
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
        onCancel={() => { setEditGroup(null); editForm.resetFields(); }}
        onOk={() => editForm.submit()}
        confirmLoading={updateGroup.isPending}
      >
        <Form form={editForm} layout="vertical" onFinish={handleUpdate}>
          <Form.Item
            name="name"
            label="Name"
            rules={[
              { pattern: /^[a-zA-Z0-9_-]+$/, message: "Only letters, numbers, hyphens, and underscores" },
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

      {/* Members Modal */}
      <Modal
        title={`Members of ${membersGroup?.name ?? ""}`}
        open={!!membersGroup}
        onCancel={() => { setMembersGroup(null); setAddMemberOpen(false); }}
        footer={null}
        width={600}
      >
        <Space direction="vertical" size="middle" style={{ display: "flex" }}>
          <Space style={{ justifyContent: "space-between", width: "100%" }}>
            <Typography.Text type="secondary">
              {(members ?? []).length} member{(members ?? []).length !== 1 ? "s" : ""}
            </Typography.Text>
            <Button
              size="small"
              icon={<UserAddOutlined />}
              onClick={() => setAddMemberOpen(true)}
            >
              Add Member
            </Button>
          </Space>

          <Table<GroupMember>
            columns={memberColumns}
            dataSource={members ?? []}
            rowKey="user_id"
            loading={membersLoading}
            pagination={false}
            size="small"
          />
        </Space>

        {/* Add Member Sub-Modal */}
        <Modal
          title="Add Member"
          open={addMemberOpen}
          onCancel={() => setAddMemberOpen(false)}
          footer={null}
        >
          <Select
            style={{ width: "100%" }}
            placeholder="Select a user"
            showSearch
            optionFilterProp="label"
            options={availableUsers.map((u) => ({
              value: u.id,
              label: `${u.username} (${u.email})`,
            }))}
            onSelect={(userId: string) => handleAddMember(userId)}
          />
        </Modal>
      </Modal>
    </>
  );
}
