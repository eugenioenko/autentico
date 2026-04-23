import { useState } from "react";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  Input,
  message,
  Alert,
} from "antd";
import { LogoutOutlined, SearchOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useIdpSessions, useForceLogoutIdpSession } from "../hooks/useIdpSessions";
import type { IdpSessionResponse } from "../types/idpSession";
import { describeUserAgent, formatActiveAppsCount } from "../lib/utils";

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function SessionsPage() {
  const [userIdFilter, setUserIdFilter] = useState("");
  const [appliedUserId, setAppliedUserId] = useState<string | undefined>();

  const { data: sessions, isLoading, error } = useIdpSessions(appliedUserId);
  const forceLogout = useForceLogoutIdpSession();

  const handleForceLogout = async (id: string) => {
    try {
      await forceLogout.mutateAsync(id);
      message.success("Device signed out");
    } catch {
      message.error("Failed to sign out device");
    }
  };

  const handleSearch = () => {
    setAppliedUserId(userIdFilter.trim() || undefined);
  };

  const columns: ColumnsType<IdpSessionResponse> = [
    {
      title: "Session ID",
      dataIndex: "id",
      key: "id",
      width: 160,
      render: (id: string) => (
        <Typography.Text copyable={{ text: id }} style={{ fontSize: 13 }}>
          {id.slice(0, 12) + "..."}
        </Typography.Text>
      ),
    },
    {
      title: "Device",
      key: "device",
      render: (_, record) => (
        <div>
          <div style={{ fontWeight: 500 }}>
            {describeUserAgent(record.user_agent)}
          </div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.ip_address || "Unknown IP"}
          </Typography.Text>
        </div>
      ),
    },
    {
      title: "User ID",
      dataIndex: "user_id",
      key: "user_id",
      ellipsis: true,
      render: (userId: string) => (
        <Typography.Text copyable={{ text: userId }} style={{ fontSize: 13 }}>
          {userId}
        </Typography.Text>
      ),
    },
    {
      title: "Apps",
      key: "apps",
      width: 140,
      render: (_, record) => (
        <Tag color={record.active_apps_count > 0 ? "blue" : "default"}>
          {formatActiveAppsCount(record.active_apps_count)}
        </Tag>
      ),
    },
    {
      title: "Last Active",
      dataIndex: "last_activity_at",
      key: "last_activity_at",
      width: 180,
      render: formatDate,
    },
    {
      title: "Signed In",
      dataIndex: "created_at",
      key: "created_at",
      width: 180,
      render: formatDate,
    },
    {
      title: "Actions",
      key: "actions",
      width: 80,
      render: (_, record) => (
        <Popconfirm
          title="Force sign out this device?"
          description="This will revoke all sessions and tokens from this device."
          onConfirm={() => handleForceLogout(record.id)}
          okText="Sign Out"
          okButtonProps={{ danger: true }}
        >
          <Button
            type="text"
            size="small"
            danger
            icon={<LogoutOutlined />}
          />
        </Popconfirm>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load sessions" />;
  }

  return (
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
      </Space>

      <Table<IdpSessionResponse>
        columns={columns}
        dataSource={sessions ?? []}
        rowKey="id"
        loading={isLoading}
        pagination={{ pageSize: 20 }}
      />
    </Space>
  );
}
