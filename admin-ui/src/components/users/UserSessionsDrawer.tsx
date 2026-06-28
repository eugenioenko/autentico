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
import { useTranslation } from "react-i18next";

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
  const { t } = useTranslation();
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
      message.success(t("users.allSessionsRevoked"));
    } catch {
      message.error(t("users.revokeSessionsFailed"));
    }
  };

  const handleForceLogout = async (id: string) => {
    try {
      await forceLogout.mutateAsync(id);
      message.success(t("sessions.deviceLoggedOut"));
    } catch {
      message.error(t("sessions.logoutFailed"));
    }
  };

  const columns: ColumnsType<IdpSessionResponse> = [
    {
      title: t("common.device"),
      key: "device",
      render: (_, record) => (
        <div>
          <div style={{ fontWeight: 500 }}>
            {describeUserAgent(record.user_agent)}
          </div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.ip_address || t("common.unknownIp")}
          </Typography.Text>
        </div>
      ),
    },
    {
      title: t("common.app"),
      key: "apps",
      width: 140,
      render: (_, record) => (
        <Tag color={record.active_apps_count > 0 ? "blue" : "default"}>
          {formatActiveAppsCount(record.active_apps_count)}
        </Tag>
      ),
    },
    {
      title: t("sessions.lastActivityAt"),
      dataIndex: "last_activity_at",
      key: "last_activity_at",
      width: 180,
      render: formatDate,
    },
    {
      title: t("sessions.loginAt"),
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
          title={t("sessions.forceLogoutDevice")}
          description={t("sessions.forceLogoutDesc")}
          onConfirm={() => handleForceLogout(record.id)}
          okText={t("sessions.logoutAction")}
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
      title={t("users.sessionsOf", { username })}
      open={open}
      onClose={onClose}
      width={720}
    >
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Typography.Text type="secondary">
            {t("users.activeDevicesForUser")}
          </Typography.Text>
          <Popconfirm
            title={t("users.revokeAllSessions")}
            description={t("users.revokeAllSessionsDesc")}
            onConfirm={handleRevokeAll}
            okText={t("users.revokeAll")}
            okButtonProps={{ danger: true }}
          >
            <Button
              danger
              size="small"
              icon={<LogoutOutlined />}
              loading={revokeAll.isPending}
              disabled={!sessions?.length}
            >
              {t("users.revokeAllSessionsBtn")}
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
          locale={{ emptyText: t("users.noActiveSessions") }}
        />
      </Space>
    </Drawer>
  );
}
