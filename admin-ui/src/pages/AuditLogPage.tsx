import { useState, useCallback, useRef } from "react";
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
  DatePicker,
} from "antd";
import { EyeOutlined } from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { SorterResult } from "antd/es/table/interface";
import type { Dayjs } from "dayjs";
import { useAuditLogs } from "../hooks/useAuditLogs";
import { useSettings } from "../hooks/useSettings";
import type { AuditLogEntry } from "../types/audit";
import type { ListParams } from "../api/users";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";

const { Text } = Typography;

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
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const { data: settings } = useSettings();
  const auditRetention = settings?.audit_log_retention ?? "0";
  const isDisabled = auditRetention === "0" || auditRetention === "";

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });
  const [searchValue, setSearchValue] = useState("");
  const [eventFilter, setEventFilter] = useState("");
  const [dateRange, setDateRange] = useState<
    [Dayjs | null, Dayjs | null] | null
  >(null);
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(
    null
  );

  const { data, isLoading, error } = useAuditLogs(listParams);

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter:
        | SorterResult<AuditLogEntry>
        | SorterResult<AuditLogEntry>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      setListParams((prev) => ({
        ...prev,
        offset:
          ((pagination.current ?? 1) - 1) *
          (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : prev.sort,
        order: s.order === "ascend" ? "asc" : "desc",
      }));
    },
    []
  );

  const handleSearch = useCallback((value: string) => {
    setListParams((prev) => ({
      ...prev,
      search: value || undefined,
      offset: 0,
    }));
  }, []);

  const handleEventFilter = useCallback((value: string) => {
    setEventFilter(value);
    setListParams((prev) => ({
      ...prev,
      event: value || undefined,
      offset: 0,
    }));
  }, []);

  const handleDateRange = useCallback(
    (dates: [Dayjs | null, Dayjs | null] | null) => {
      setDateRange(dates);
      setListParams((prev) => {
        const next: ListParams = { ...prev, offset: 0 };
        if (dates && dates[0]) {
          next.created_at_from = dates[0].startOf("day").toISOString();
        } else {
          delete next.created_at_from;
        }
        if (dates && dates[1]) {
          next.created_at_to = dates[1].endOf("day").toISOString();
        } else {
          delete next.created_at_to;
        }
        return next;
      });
    },
    []
  );

  const columns: ColumnsType<AuditLogEntry> = [
    {
      title: "Event",
      dataIndex: "event",
      key: "event",
      width: 200,
      sorter: true,
      sortOrder:
        listParams.sort === "event"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      render: (event: string) => (
        <Tag color={EVENT_COLORS[event] || "default"}>{formatEvent(event)}</Tag>
      ),
    },
    {
      title: "Actor",
      dataIndex: "actor_username",
      key: "actor_username",
      width: 160,
      render: (username: string) =>
        username ? (
          <Text copyable={{ text: username }} ellipsis>
            {username}
          </Text>
        ) : (
          <Text type="secondary">—</Text>
        ),
    },
    {
      title: "Target",
      key: "target",
      width: 200,
      ellipsis: true,
      render: (_: unknown, record: AuditLogEntry) => {
        if (!record.target_type && !record.target_id)
          return <Text type="secondary">—</Text>;
        if (!record.target_id)
          return <Text>{record.target_type}</Text>;
        return (
          <Text copyable={{ text: record.target_id }} ellipsis>
            {record.target_type}: {record.target_id}
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
      title: "Time",
      dataIndex: "created_at",
      key: "created_at",
      width: 180,
      sorter: true,
      sortOrder:
        listParams.sort === "created_at"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      render: formatDate,
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
    <>
      <Space
        style={{
          justifyContent: "space-between",
          width: "100%",
          flexShrink: 0,
        }}
      >
        <Typography.Title level={4} style={{ margin: 0 }}>
          Audit Log
        </Typography.Title>
        <Space>
          <Select
            style={{ width: 200 }}
            options={EVENT_OPTIONS}
            value={eventFilter}
            onChange={handleEventFilter}
          />
          <DatePicker.RangePicker
            value={dateRange}
            onChange={handleDateRange}
            allowClear
          />
          <Input.Search
            placeholder="Search actor, target, IP..."
            allowClear
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onSearch={handleSearch}
            style={{ width: 250 }}
          />
        </Space>
      </Space>

      {isDisabled && (
        <Alert
          type="info"
          showIcon
          message="Audit logging is disabled"
          description='To start recording events, set the audit log retention in Settings > Security & Validation > Audit Log (e.g. 720h for 30 days, or -1 to keep forever).'
          style={{ marginTop: 16, flexShrink: 0 }}
        />
      )}

      <div
        ref={tableContainerRef}
        style={{ flex: 1, overflow: "hidden", marginTop: 16 }}
      >
        <Table<AuditLogEntry>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey="id"
          loading={isLoading}
          onChange={handleTableChange}
          scroll={scrollY ? { y: scrollY } : undefined}
          pagination={{
            current:
              Math.floor(
                (listParams.offset ?? 0) /
                  (listParams.limit ?? DEFAULT_PAGE_SIZE)
              ) + 1,
            pageSize: listParams.limit ?? DEFAULT_PAGE_SIZE,
            total: data?.total ?? 0,
            showSizeChanger: true,
            pageSizeOptions: PAGE_SIZE_OPTIONS,
            showTotal: (total) => `${total} events`,
          }}
        />
      </div>

      <Drawer
        title="Event Detail"
        open={!!selectedEntry}
        onClose={() => setSelectedEntry(null)}
        width={480}
      >
        {selectedEntry && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="ID">
              {selectedEntry.id}
            </Descriptions.Item>
            <Descriptions.Item label="Event">
              <Tag color={EVENT_COLORS[selectedEntry.event] || "default"}>
                {formatEvent(selectedEntry.event)}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Time">
              {formatDate(selectedEntry.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label="Actor ID">
              {selectedEntry.actor_id || "—"}
            </Descriptions.Item>
            <Descriptions.Item label="Actor Username">
              {selectedEntry.actor_username || "—"}
            </Descriptions.Item>
            <Descriptions.Item label="Target Type">
              {selectedEntry.target_type || "—"}
            </Descriptions.Item>
            <Descriptions.Item label="Target ID">
              {selectedEntry.target_id || "—"}
            </Descriptions.Item>
            <Descriptions.Item label="IP Address">
              {selectedEntry.ip_address || "—"}
            </Descriptions.Item>
            <Descriptions.Item label="Detail">
              {selectedEntry.detail ? (
                <pre
                  style={{
                    margin: 0,
                    fontSize: 12,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                  }}
                >
                  {JSON.stringify(JSON.parse(selectedEntry.detail), null, 2)}
                </pre>
              ) : (
                "—"
              )}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </>
  );
}
