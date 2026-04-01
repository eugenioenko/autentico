import { useState } from "react";
import {
  Typography,
  Table,
  Tag,
  Space,
  Select,
  Input,
  Alert,
  Button,
  Drawer,
  Descriptions,
} from "antd";
import { SearchOutlined, EyeOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useAuditLogs } from "../hooks/useAuditLogs";
import { useSettings } from "../hooks/useSettings";
import type { AuditLogEntry } from "../types/audit";

const { Title, Text } = Typography;

const EVENT_OPTIONS = [
  { label: "All Events", value: "" },
  { label: "Login Success", value: "login_success" },
  { label: "Login Failed", value: "login_failed" },
  { label: "MFA Success", value: "mfa_success" },
  { label: "MFA Failed", value: "mfa_failed" },
  { label: "Passkey Login Success", value: "passkey_login_success" },
  { label: "Passkey Login Failed", value: "passkey_login_failed" },
  { label: "Password Changed", value: "password_changed" },
  { label: "Password Reset Requested", value: "password_reset_requested" },
  { label: "Password Reset Completed", value: "password_reset_completed" },
  { label: "User Created", value: "user_created" },
  { label: "User Updated", value: "user_updated" },
  { label: "User Deactivated", value: "user_deactivated" },
  { label: "User Unlocked", value: "user_unlocked" },
  { label: "MFA Enrolled", value: "mfa_enrolled" },
  { label: "MFA Disabled", value: "mfa_disabled" },
  { label: "Passkey Added", value: "passkey_added" },
  { label: "Passkey Removed", value: "passkey_removed" },
  { label: "Logout", value: "logout" },
  { label: "Session Revoked", value: "session_revoked" },
  { label: "Client Created", value: "client_created" },
  { label: "Client Updated", value: "client_updated" },
  { label: "Client Deleted", value: "client_deleted" },
  { label: "Settings Updated", value: "settings_updated" },
  { label: "Settings Imported", value: "settings_imported" },
  { label: "Federation Created", value: "federation_created" },
  { label: "Federation Updated", value: "federation_updated" },
  { label: "Federation Deleted", value: "federation_deleted" },
  { label: "Deletion Approved", value: "deletion_approved" },
];

const EVENT_COLORS: Record<string, string> = {
  login_success: "success",
  login_failed: "error",
  mfa_success: "success",
  mfa_failed: "error",
  passkey_login_success: "success",
  passkey_login_failed: "error",
  password_changed: "warning",
  password_reset_requested: "warning",
  password_reset_completed: "warning",
  user_created: "processing",
  user_updated: "processing",
  user_deactivated: "error",
  user_unlocked: "processing",
  mfa_enrolled: "processing",
  mfa_disabled: "warning",
  passkey_added: "processing",
  passkey_removed: "warning",
  logout: "default",
  session_revoked: "default",
  client_created: "processing",
  client_updated: "processing",
  client_deleted: "error",
  settings_updated: "processing",
  settings_imported: "processing",
  federation_created: "processing",
  federation_updated: "processing",
  federation_deleted: "error",
  deletion_approved: "error",
};

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

function formatEvent(event: string): string {
  return event.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function AuditLogPage() {
  const { data: settings } = useSettings();
  const auditRetention = settings?.audit_log_retention ?? "0";
  const isDisabled = auditRetention === "0" || auditRetention === "";

  const [eventFilter, setEventFilter] = useState("");
  const [actorSearch, setActorSearch] = useState("");
  const [appliedActorId, setAppliedActorId] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);

  const { data, isLoading, error } = useAuditLogs({
    event: eventFilter || undefined,
    actor_id: appliedActorId || undefined,
    limit: pageSize,
    offset: (page - 1) * pageSize,
  });

  const columns: ColumnsType<AuditLogEntry> = [
    {
      title: "Time",
      dataIndex: "created_at",
      key: "created_at",
      width: 180,
      render: formatDate,
    },
    {
      title: "Event",
      dataIndex: "event",
      key: "event",
      width: 200,
      render: (event: string) => (
        <Tag color={EVENT_COLORS[event] || "default"}>{formatEvent(event)}</Tag>
      ),
    },
    {
      title: "Actor",
      dataIndex: "actor_username",
      key: "actor_username",
      width: 160,
      render: (username: string) => username || <Text type="secondary">—</Text>,
    },
    {
      title: "Target",
      key: "target",
      width: 160,
      render: (_: unknown, record: AuditLogEntry) => {
        if (!record.target_type && !record.target_id) return <Text type="secondary">—</Text>;
        return (
          <Text>
            {record.target_type}
            {record.target_id ? `: ${record.target_id.substring(0, 12)}` : ""}
          </Text>
        );
      },
    },
    {
      title: "IP",
      dataIndex: "ip_address",
      key: "ip_address",
      width: 130,
      render: (ip: string) => ip || <Text type="secondary">—</Text>,
    },
    {
      title: "Detail",
      dataIndex: "detail",
      key: "detail",
      ellipsis: true,
      render: (detail: string) =>
        detail ? (
          <Text code style={{ fontSize: 11 }}>
            {detail}
          </Text>
        ) : (
          <Text type="secondary">—</Text>
        ),
    },
    {
      title: "",
      key: "actions",
      width: 50,
      render: (_: unknown, record: AuditLogEntry) => (
        <Button
          type="text"
          size="small"
          icon={<EyeOutlined />}
          onClick={() => setSelectedEntry(record)}
        />
      ),
    },
  ];

  if (error) return <Alert type="error" message="Failed to load audit logs" />;

  return (
    <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <div>
        <Title level={2}>Audit Log</Title>
        <Text type="secondary">Security events and administrative actions.</Text>
      </div>

      {isDisabled && (
        <Alert
          type="info"
          showIcon
          message="Audit logging is disabled"
          description="To start recording events, set the audit log retention in Settings > Security & Validation > Audit Log (e.g. 720h for 30 days, or -1 to keep forever)."
        />
      )}

      <Space wrap>
        <Select
          style={{ width: 220 }}
          options={EVENT_OPTIONS}
          value={eventFilter}
          onChange={(v) => {
            setEventFilter(v);
            setPage(1);
          }}
        />
        <Input
          placeholder="Filter by user ID"
          prefix={<SearchOutlined />}
          style={{ width: 240 }}
          value={actorSearch}
          onChange={(e) => setActorSearch(e.target.value)}
          onPressEnter={() => {
            setAppliedActorId(actorSearch);
            setPage(1);
          }}
          allowClear
          onClear={() => {
            setAppliedActorId("");
            setPage(1);
          }}
        />
      </Space>

      <Table
        columns={columns}
        dataSource={data?.data}
        rowKey="id"
        loading={isLoading}
        size="small"
        scroll={{ x: "max-content" }}
        style={{ whiteSpace: "nowrap" }}
        pagination={{
          current: page,
          pageSize,
          total: data?.total || 0,
          showSizeChanger: true,
          pageSizeOptions: ["10", "20", "50"],
          showTotal: (total) => `${total} events`,
          onChange: (p, ps) => {
            setPage(p);
            setPageSize(ps);
          },
        }}
      />

      <Drawer
        title="Event Detail"
        open={!!selectedEntry}
        onClose={() => setSelectedEntry(null)}
        width={480}
      >
        {selectedEntry && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="ID">{selectedEntry.id}</Descriptions.Item>
            <Descriptions.Item label="Event">
              <Tag color={EVENT_COLORS[selectedEntry.event] || "default"}>
                {formatEvent(selectedEntry.event)}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Time">{formatDate(selectedEntry.created_at)}</Descriptions.Item>
            <Descriptions.Item label="Actor ID">{selectedEntry.actor_id || "—"}</Descriptions.Item>
            <Descriptions.Item label="Actor Username">{selectedEntry.actor_username || "—"}</Descriptions.Item>
            <Descriptions.Item label="Target Type">{selectedEntry.target_type || "—"}</Descriptions.Item>
            <Descriptions.Item label="Target ID">{selectedEntry.target_id || "—"}</Descriptions.Item>
            <Descriptions.Item label="IP Address">{selectedEntry.ip_address || "—"}</Descriptions.Item>
            <Descriptions.Item label="Detail">
              {selectedEntry.detail ? (
                <pre style={{ margin: 0, fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                  {JSON.stringify(JSON.parse(selectedEntry.detail), null, 2)}
                </pre>
              ) : "—"}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </Space>
  );
}
