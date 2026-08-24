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
import CopyText from "../components/CopyText";
import { useTranslation } from "react-i18next";

const { Text } = Typography;

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

const EVENT_KEY_MAP: Record<string, string> = {
  login_success: "auditLog.loginSuccess",
  login_failed: "auditLog.loginFailed",
  mfa_success: "auditLog.mfaSuccess",
  mfa_failed: "auditLog.mfaFailed",
  passkey_login_success: "auditLog.passkeyLoginSuccess",
  passkey_login_failed: "auditLog.passkeyLoginFailed",
  password_changed: "auditLog.passwordChanged",
  password_reset_requested: "auditLog.passwordResetRequested",
  password_reset_completed: "auditLog.passwordResetCompleted",
  user_created: "auditLog.userCreated",
  user_updated: "auditLog.userUpdated",
  user_deactivated: "auditLog.userDeactivated",
  user_unlocked: "auditLog.userUnlocked",
  mfa_enrolled: "auditLog.mfaEnrolled",
  mfa_disabled: "auditLog.mfaDisabled",
  passkey_added: "auditLog.passkeyAdded",
  passkey_removed: "auditLog.passkeyRemoved",
  logout: "auditLog.logout",
  session_revoked: "auditLog.sessionRevoked",
  client_created: "auditLog.clientCreated",
  client_updated: "auditLog.clientUpdated",
  client_deleted: "auditLog.clientDeleted",
  settings_updated: "auditLog.settingsUpdated",
  settings_imported: "auditLog.settingsImported",
  federation_created: "auditLog.federationCreated",
  federation_updated: "auditLog.federationUpdated",
  federation_deleted: "auditLog.federationDeleted",
  deletion_approved: "auditLog.deletionApproved",
};

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function AuditLogPage() {
  const { t } = useTranslation();
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

  const EVENT_OPTIONS = [
    { label: t("auditLog.allEvents"), value: "" },
    ...Object.entries(EVENT_KEY_MAP).map(([value, key]) => ({
      label: t(key),
      value,
    })),
  ];

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
      title: t("common.event"),
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
        <Tag color={EVENT_COLORS[event] || "default"}>
          {t(EVENT_KEY_MAP[event] || "common.noData")}
        </Tag>
      ),
    },
    {
      title: t("common.actor"),
      dataIndex: "actor_username",
      key: "actor_username",
      width: 160,
      render: (username: string) =>
        username ? (
          <CopyText text={username} />
        ) : (
          <Text type="secondary">\u2014</Text>
        ),
    },
    {
      title: t("common.target"),
      key: "target",
      width: 200,
      ellipsis: true,
      render: (_: unknown, record: AuditLogEntry) => {
        if (!record.target_type && !record.target_id)
          return <Text type="secondary">\u2014</Text>;
        if (!record.target_id)
          return <Text>{record.target_type}</Text>;
        return (
          <CopyText text={record.target_id}>
            {record.target_type}: {record.target_id}
          </CopyText>
        );
      },
    },
    {
      title: t("common.ip"),
      dataIndex: "ip_address",
      key: "ip_address",
      width: 130,
      render: (ip: string) => ip || <Text type="secondary">\u2014</Text>,
    },
    {
      title: t("common.details"),
      dataIndex: "detail",
      key: "detail",
      ellipsis: true,
      render: (detail: string) =>
        detail ? (
          <Text code style={{ fontSize: 11 }}>
            {detail}
          </Text>
        ) : (
          <Text type="secondary">\u2014</Text>
        ),
    },
    {
      title: t("common.time"),
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

  if (error) return <Alert type="error" message={t("auditLog.failedToLoadAuditLog")} />;

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
          {t("auditLog.title")}
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
            placeholder={t("auditLog.searchAuditLog")}
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
          message={t("auditLog.auditLogDisabled")}
          description={t("auditLog.auditLogDisabledDesc")}
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
            showTotal: (total) => t("auditLog.totalEvents", { total }),
          }}
        />
      </div>

      <Drawer
        title={t("auditLog.eventDetail")}
        open={!!selectedEntry}
        onClose={() => setSelectedEntry(null)}
        width={480}
      >
        {selectedEntry && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label={t("common.id")}>
              {selectedEntry.id}
            </Descriptions.Item>
            <Descriptions.Item label={t("common.event")}>
              <Tag color={EVENT_COLORS[selectedEntry.event] || "default"}>
                {t(EVENT_KEY_MAP[selectedEntry.event] || "common.noData")}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t("common.time")}>
              {formatDate(selectedEntry.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label={t("auditLog.actorId")}>
              {selectedEntry.actor_id || "\u2014"}
            </Descriptions.Item>
            <Descriptions.Item label={t("auditLog.actorUsername")}>
              {selectedEntry.actor_username || "\u2014"}
            </Descriptions.Item>
            <Descriptions.Item label={t("auditLog.targetType")}>
              {selectedEntry.target_type || "\u2014"}
            </Descriptions.Item>
            <Descriptions.Item label={t("auditLog.targetId")}>
              {selectedEntry.target_id || "\u2014"}
            </Descriptions.Item>
            <Descriptions.Item label={t("auditLog.ipAddress")}>
              {selectedEntry.ip_address || "\u2014"}
            </Descriptions.Item>
            <Descriptions.Item label={t("common.details")}>
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
                "\u2014"
              )}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </>
  );
}
