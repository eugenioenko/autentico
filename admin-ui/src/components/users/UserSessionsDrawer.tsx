import {
  Drawer,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  Typography,
  App,
} from "antd";
import { LogoutOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import {
  useUserIdpSessions,
  useForceLogoutIdpSession,
  useRevokeAllUserSessions,
} from "../../hooks/useIdpSessions";
import type { IdpSessionResponse } from "../../types/idpSession";
import { describeUserAgent, formatActiveAppsCount } from "../../lib/utils";

interface UserSessionsDrawerProps {
  open: boolean;
  userId: string | null;
  username: string;
  onClose: () => void;
}

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function UserSessionsDrawer({
  open,
  userId,
  username,
  onClose,
}: UserSessionsDrawerProps) {
  const { message } = App.useApp();
  const { data: sessions, isLoading } = useUserIdpSessions(
    open ? userId : null
  );
  const forceLogout = useForceLogoutIdpSession();
  const revokeAll = useRevokeAllUserSessions();

  const handleRevokeAll = async () => {
    if (!userId) return;
    try {
      await revokeAll.mutateAsync(userId);
      message.success("All sessions revoked");
    } catch {
      message.error("Failed to revoke sessions");
    }
  };

  const handleForceLogout = async (id: string) => {
    try {
      await forceLogout.mutateAsync(id);
      message.success("Device signed out");
    } catch {
      message.error("Failed to sign out device");
    }
  };

  const columns: ColumnsType<IdpSessionResponse> = [
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
      title: "",
      key: "actions",
      width: 50,
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

  return (
    <Drawer
      title={`Sessions for ${username}`}
      open={open}
      onClose={onClose}
      width={720}
    >
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Typography.Text type="secondary">
            Active devices where this user is signed in.
          </Typography.Text>
          <Popconfirm
            title="Revoke all sessions?"
            description="This will revoke all tokens, sessions, and sign out every device for this user."
            onConfirm={handleRevokeAll}
            okText="Revoke All"
            okButtonProps={{ danger: true }}
          >
            <Button
              danger
              size="small"
              icon={<LogoutOutlined />}
              loading={revokeAll.isPending}
              disabled={!sessions?.length}
            >
              Revoke All Sessions
            </Button>
          </Popconfirm>
        </div>

        <Table<IdpSessionResponse>
          columns={columns}
          dataSource={sessions ?? []}
          rowKey="id"
          loading={isLoading}
          pagination={false}
          size="small"
          locale={{ emptyText: "No active sessions" }}
        />
      </Space>
    </Drawer>
  );
}
