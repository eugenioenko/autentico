import { useState, useEffect, useCallback, useRef } from "react";
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
  Input,
} from "antd";
import {
  PlusOutlined,
  EditOutlined,
  StopOutlined,
  UnlockOutlined,
  TeamOutlined,
  LaptopOutlined,
} from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { FilterValue, SorterResult } from "antd/es/table/interface";
import { useUsers, useDeleteUser, useUnlockUser } from "../hooks/useUsers";
import type { ListParams } from "../api/users";
import type { UserResponseExt } from "../types/user";
import UserCreateForm from "../components/users/UserCreateForm";
import UserEditForm from "../components/users/UserEditForm";
import UserGroupsDrawer from "../components/users/UserGroupsDrawer";
import UserSessionsDrawer from "../components/users/UserSessionsDrawer";
import TagOverflow from "../components/TagOverflow";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";

function isLocked(record: UserResponseExt): boolean {
  return !!record.locked_until && new Date(record.locked_until) > new Date();
}

export default function UsersPage() {
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });
  const [searchValue, setSearchValue] = useState("");

  const { data, isLoading, error } = useUsers(listParams);
  const deleteUser = useDeleteUser();
  const unlockUserMutation = useUnlockUser();
  const location = useLocation();

  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<UserResponseExt | null>(null);
  const [groupsUser, setGroupsUser] = useState<UserResponseExt | null>(null);
  const [sessionsUser, setSessionsUser] = useState<UserResponseExt | null>(
    null
  );

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

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      filters: Record<string, FilterValue | null>,
      sorter: SorterResult<UserResponseExt> | SorterResult<UserResponseExt>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      const newParams: ListParams = {
        ...listParams,
        offset: ((pagination.current ?? 1) - 1) * (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : "created_at",
        order: s.order === "ascend" ? "asc" : "desc",
      };

      if (filters.role?.length) {
        newParams.role = filters.role[0] as string;
      } else {
        delete newParams.role;
      }

      if (filters.verified?.length) {
        newParams.is_email_verified = filters.verified[0] as string;
      } else {
        delete newParams.is_email_verified;
      }

      if (filters.mfa?.length) {
        newParams.totp_verified = filters.mfa[0] as string;
      } else {
        delete newParams.totp_verified;
      }

      setListParams(newParams);
    },
    [listParams]
  );

  const handleSearch = useCallback(
    (value: string) => {
      setListParams((prev) => ({
        ...prev,
        search: value || undefined,
        offset: 0,
      }));
    },
    []
  );

  const columns: ColumnsType<UserResponseExt> = [
    {
      title: "Username",
      dataIndex: "username",
      key: "username",
      sorter: true,
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
      sorter: true,
    },
    {
      title: "Role",
      dataIndex: "role",
      key: "role",
      sorter: true,
      filters: [
        { text: "Admin", value: "admin" },
        { text: "User", value: "user" },
      ],
      filterMultiple: false,
      render: (role: string) => (
        <Tag color={role === "admin" ? "red" : "blue"}>{role}</Tag>
      ),
    },
    {
      title: "MFA",
      dataIndex: "totp_verified",
      key: "mfa",
      filters: [
        { text: "Enrolled", value: "1" },
        { text: "No", value: "0" },
      ],
      filterMultiple: false,
      render: (verified: boolean) => (
        <Tag color={verified ? "success" : "default"}>
          {verified ? "Enrolled" : "No"}
        </Tag>
      ),
    },
    {
      title: "Verified",
      dataIndex: "is_email_verified",
      key: "verified",
      filters: [
        { text: "Yes", value: "1" },
        { text: "No", value: "0" },
      ],
      filterMultiple: false,
      render: (verified: boolean) => (
        <Tag color={verified ? "success" : "warning"}>
          {verified ? "Yes" : "No"}
        </Tag>
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
            <Tooltip
              title={`${record.failed_login_attempts} failed attempt(s)`}
            >
              <Tag color="gold">{record.failed_login_attempts} failed</Tag>
            </Tooltip>
          );
        }
        return <Tag color="green">Active</Tag>;
      },
    },
    {
      title: "Groups",
      key: "groups",
      render: (_, record) => <TagOverflow items={record.groups} />,
    },
    {
      title: "Created",
      dataIndex: "created_at",
      key: "created_at",
      sorter: true,
      render: (date: string) =>
        date ? new Date(date).toLocaleDateString() : "-",
    },
    {
      title: "Actions",
      key: "actions",
      render: (_, record) => (
        <Space>
          <Popconfirm
            title="Deactivate this user?"
            description="The user will no longer be able to log in."
            onConfirm={() => handleDelete(record.id!)}
            okText="Deactivate"
            okButtonProps={{ danger: true }}
          >
            <Button type="text" size="small" danger icon={<StopOutlined />} />
          </Popconfirm>
          <Button
            type="text"
            size="small"
            icon={<TeamOutlined />}
            onClick={() => setGroupsUser(record)}
          />
          <Button
            type="text"
            size="small"
            icon={<LaptopOutlined />}
            onClick={() => setSessionsUser(record)}
          />
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
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load users" />;
  }

  return (
    <>
      <Space style={{ justifyContent: "space-between", width: "100%", flexShrink: 0 }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          Users
        </Typography.Title>
        <Space>
          <Input.Search
            placeholder="Search users..."
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
            Create User
          </Button>
        </Space>
      </Space>

      <div ref={tableContainerRef} style={{ flex: 1, overflow: "hidden", marginTop: 16 }}>
        <Table<UserResponseExt>
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
            showTotal: (total) => `${total} users`,
          }}
        />
      </div>

      <UserCreateForm
        open={createOpen}
        onClose={() => setCreateOpen(false)}
      />

      <UserEditForm
        open={!!editUser}
        user={editUser}
        onClose={() => setEditUser(null)}
      />

      <UserGroupsDrawer
        open={!!groupsUser}
        userId={groupsUser?.id ?? null}
        username={groupsUser?.username ?? ""}
        onClose={() => setGroupsUser(null)}
      />

      <UserSessionsDrawer
        open={!!sessionsUser}
        userId={sessionsUser?.id ?? null}
        username={sessionsUser?.username ?? ""}
        onClose={() => setSessionsUser(null)}
      />
    </>
  );
}
