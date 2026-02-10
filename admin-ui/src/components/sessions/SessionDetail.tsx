import { Drawer, Descriptions, Tag } from "antd";
import type { SessionResponse } from "../../types/session";

interface SessionDetailProps {
  open: boolean;
  session: SessionResponse | null;
  onClose: () => void;
}

const STATUS_COLORS: Record<string, string> = {
  active: "success",
  expired: "warning",
  deactivated: "error",
};

function formatDate(date: string | null): string {
  if (!date) return "-";
  return new Date(date).toLocaleString();
}

export default function SessionDetail({
  open,
  session,
  onClose,
}: SessionDetailProps) {
  if (!session) return null;

  return (
    <Drawer
      title={`Session: ${session.id.slice(0, 12)}...`}
      open={open}
      onClose={onClose}
      width={520}
    >
      <Descriptions column={1} bordered size="small">
        <Descriptions.Item label="Session ID">{session.id}</Descriptions.Item>
        <Descriptions.Item label="User ID">{session.user_id}</Descriptions.Item>
        <Descriptions.Item label="Status">
          <Tag color={STATUS_COLORS[session.status]}>{session.status}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="IP Address">
          {session.ip_address || "-"}
        </Descriptions.Item>
        <Descriptions.Item label="User Agent">
          {session.user_agent || "-"}
        </Descriptions.Item>
        <Descriptions.Item label="Location">
          {session.location || "-"}
        </Descriptions.Item>
        <Descriptions.Item label="Device ID">
          {session.device_id ?? "-"}
        </Descriptions.Item>
        <Descriptions.Item label="Created">
          {formatDate(session.created_at)}
        </Descriptions.Item>
        <Descriptions.Item label="Expires">
          {formatDate(session.expires_at)}
        </Descriptions.Item>
        <Descriptions.Item label="Last Activity">
          {formatDate(session.last_activity_at)}
        </Descriptions.Item>
        <Descriptions.Item label="Deactivated">
          {formatDate(session.deactivated_at)}
        </Descriptions.Item>
      </Descriptions>
    </Drawer>
  );
}
