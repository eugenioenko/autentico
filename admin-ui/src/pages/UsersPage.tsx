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
} from "antd";
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useUsers, useDeleteUser } from "../hooks/useUsers";
import type { UserResponse } from "../types/user";
import UserCreateForm from "../components/users/UserCreateForm";
import UserEditForm from "../components/users/UserEditForm";

export default function UsersPage() {
  const { data: users, isLoading, error } = useUsers();
  const deleteUser = useDeleteUser();
  const location = useLocation();

  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<UserResponse | null>(null);

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

  const columns: ColumnsType<UserResponse> = [
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

        <Table<UserResponse>
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
