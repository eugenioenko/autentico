import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  message,
  Alert,
  Tooltip,
} from "antd";
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  UnlockOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useUsers, useDeleteUser, useUnlockUser } from "../hooks/useUsers";
import type { UserResponseExt } from "../types/user";
import UserCreateForm from "../components/users/UserCreateForm";
import UserEditForm from "../components/users/UserEditForm";

function isLocked(record: UserResponseExt): boolean {
  return !!record.locked_until && new Date(record.locked_until) > new Date();
}

export default function UsersPage() {
  const { data: users, isLoading, error } = useUsers();
  const deleteUser = useDeleteUser();
  const unlockUserMutation = useUnlockUser();
  const location = useLocation();

  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<UserResponseExt | null>(null);

  useEffect(() => {
    if ((location.state as { create?: boolean })?.create) {
      setCreateOpen(true);
      window.history.replaceState({}, "");
    }
  }, [location.state]);

  const handleDelete = async (id: string) => {
    try {
      await deleteUser.mutateAsync(id);
      message.success("User deactivated");
    } catch {
      message.error("Failed to deactivate user");
    }
  };

  const handleUnlock = async (id: string) => {
    try {
      await unlockUserMutation.mutateAsync(id);
      message.success("User unlocked");
    } catch {
      message.error("Failed to unlock user");
    }
  };

  const columns: ColumnsType<UserResponseExt> = [
    {
      title: "Username",
      dataIndex: "username",
      key: "username",
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
    },
    {
      title: "Role",
      dataIndex: "role",
      key: "role",
      render: (role: string) => (
        <Tag color={role === "admin" ? "red" : "blue"}>{role}</Tag>
      ),
    },
    {
      title: "Status",
      key: "status",
      render: (_, record) => {
        if (isLocked(record)) {
          return <Tag color="orange">Locked</Tag>;
        }
        if (record.failed_login_attempts && record.failed_login_attempts > 0) {
          return (
            <Tooltip title={`${record.failed_login_attempts} failed attempt(s)`}>
              <Tag color="gold">
                {record.failed_login_attempts} failed
              </Tag>
            </Tooltip>
          );
        }
        return <Tag color="green">Active</Tag>;
      },
    },
    {
      title: "Created",
      dataIndex: "created_at",
      key: "created_at",
      render: (date: string) =>
        date ? new Date(date).toLocaleDateString() : "-",
    },
    {
      title: "Actions",
      key: "actions",
      render: (_, record) => (
        <Space>
          <Button
            type="text"
            size="small"
            icon={<EditOutlined />}
            onClick={() => setEditUser(record)}
          />
          {isLocked(record) && (
            <Popconfirm
              title="Unlock this user?"
              description="This will reset failed login attempts and remove the lockout."
              onConfirm={() => handleUnlock(record.id!)}
              okText="Unlock"
            >
              <Button
                type="text"
                size="small"
                icon={<UnlockOutlined />}
              />
            </Popconfirm>
          )}
          <Popconfirm
            title="Deactivate this user?"
            description="The user will no longer be able to log in."
            onConfirm={() => handleDelete(record.id!)}
            okText="Deactivate"
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
    return <Alert type="error" message="Failed to load users" />;
  }

  return (
    <>
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <Space style={{ justifyContent: "space-between", width: "100%" }}>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Users
          </Typography.Title>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            Create User
          </Button>
        </Space>

        <Table<UserResponseExt>
          columns={columns}
          dataSource={users ?? []}
          rowKey="id"
          loading={isLoading}
          pagination={false}
        />
      </Space>

      <UserCreateForm
        open={createOpen}
        onClose={() => setCreateOpen(false)}
      />

      <UserEditForm
        open={!!editUser}
        user={editUser}
        onClose={() => setEditUser(null)}
      />
    </>
  );
}
