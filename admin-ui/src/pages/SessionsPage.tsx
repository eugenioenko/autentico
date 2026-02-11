import { useState } from "react";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  Input,
  Select,
  message,
  Alert,
} from "antd";
import {
  StopOutlined,
  EyeOutlined,
  SearchOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useSessions, useDeactivateSession } from "../hooks/useSessions";
import type { SessionResponse } from "../types/session";
import SessionDetail from "../components/sessions/SessionDetail";

const STATUS_COLORS: Record<string, string> = {
  active: "success",
  expired: "warning",
  deactivated: "error",
};

const STATUS_OPTIONS = [
  { label: "All", value: "" },
  { label: "Active", value: "active" },
  { label: "Expired", value: "expired" },
  { label: "Deactivated", value: "deactivated" },
];

function formatDate(date: string | null): string {
  if (!date) return "-";
  return new Date(date).toLocaleString();
}

export default function SessionsPage() {
  const [userIdFilter, setUserIdFilter] = useState("");
  const [appliedUserId, setAppliedUserId] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState("");

  const { data: sessions, isLoading, error } = useSessions(appliedUserId);
  const deactivateSession = useDeactivateSession();

  const [detailSession, setDetailSession] = useState<SessionResponse | null>(
    null
  );

  const handleDeactivate = async (id: string) => {
    try {
      await deactivateSession.mutateAsync(id);
      message.success("Session deactivated");
    } catch {
      message.error("Failed to deactivate session");
    }
  };

  const handleSearch = () => {
    setAppliedUserId(userIdFilter.trim() || undefined);
  };

  const filteredSessions = statusFilter
    ? sessions?.filter((s) => s.status === statusFilter)
    : sessions;

  const columns: ColumnsType<SessionResponse> = [
    {
      title: "Session ID",
      dataIndex: "id",
      key: "id",
      render: (id: string) => id.slice(0, 12) + "...",
      ellipsis: true,
    },
    {
      title: "User ID",
      dataIndex: "user_id",
      key: "user_id",
      ellipsis: true,
    },
    {
      title: "IP Address",
      dataIndex: "ip_address",
      key: "ip_address",
    },
    {
      title: "User Agent",
      dataIndex: "user_agent",
      key: "user_agent",
      ellipsis: true,
    },
    {
      title: "Created",
      dataIndex: "created_at",
      key: "created_at",
      render: formatDate,
    },
    {
      title: "Expires",
      dataIndex: "expires_at",
      key: "expires_at",
      render: formatDate,
    },
    {
      title: "Status",
      dataIndex: "status",
      key: "status",
      render: (status: string) => (
        <Tag color={STATUS_COLORS[status]}>{status}</Tag>
      ),
    },
    {
      title: "Actions",
      key: "actions",
      render: (_, record) => (
        <Space>
          <Button
            type="text"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => setDetailSession(record)}
          />
          {record.status === "active" && (
            <Popconfirm
              title="Deactivate this session?"
              description="The user will be logged out."
              onConfirm={() => handleDeactivate(record.id)}
              okText="Deactivate"
              okButtonProps={{ danger: true }}
            >
              <Button
                type="text"
                size="small"
                danger
                icon={<StopOutlined />}
              />
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load sessions" />;
  }

  return (
    <>
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          Sessions
        </Typography.Title>

        <Space wrap>
          <Input
            placeholder="Filter by User ID"
            value={userIdFilter}
            onChange={(e) => setUserIdFilter(e.target.value)}
            onPressEnter={handleSearch}
            style={{ width: 280 }}
            suffix={
              <Button
                type="text"
                size="small"
                icon={<SearchOutlined />}
                onClick={handleSearch}
              />
            }
            allowClear
            onClear={() => {
              setUserIdFilter("");
              setAppliedUserId(undefined);
            }}
          />
          <Select
            value={statusFilter}
            onChange={setStatusFilter}
            options={STATUS_OPTIONS}
            style={{ width: 140 }}
          />
        </Space>

        <Table<SessionResponse>
          columns={columns}
          dataSource={filteredSessions ?? []}
          rowKey="id"
          loading={isLoading}
          pagination={{ pageSize: 20 }}
        />
      </Space>

      <SessionDetail
        open={!!detailSession}
        session={detailSession}
        onClose={() => setDetailSession(null)}
      />
    </>
  );
}
