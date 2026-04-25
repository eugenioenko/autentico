import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  Input,
  Select,
  Alert,
  Drawer,
  Descriptions,
  DatePicker,
  App,
} from "antd";
import {
  LogoutOutlined,
  ArrowLeftOutlined,
  UnorderedListOutlined,
  InfoCircleOutlined,
  DeleteOutlined,
} from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { SorterResult } from "antd/es/table/interface";
import type { Dayjs } from "dayjs";
import {
  useIdpSessions,
  useForceLogoutIdpSession,
  useIdpSessionSessions,
  useDeactivateOAuthSession,
} from "../hooks/useIdpSessions";
import type { ListParams } from "../api/users";
import type {
  IdpSessionResponse,
  OAuthSessionResponse,
} from "../types/idpSession";
import { describeUserAgent } from "../lib/utils";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";

function formatDate(date: string | null): string {
  if (!date) return "—";
  return new Date(date).toLocaleString();
}


function statusTag(status: string) {
  const color =
    status === "active" ? "green" : status === "expired" ? "orange" : "red";
  return <Tag color={color}>{status}</Tag>;
}

function OAuthSessionDetailDrawer({
  session,
  onClose,
}: {
  session: OAuthSessionResponse | null;
  onClose: () => void;
}) {
  return (
    <Drawer
      title="Session Details"
      open={!!session}
      onClose={onClose}
      width={480}
    >
      {session && (
        <Descriptions column={1} bordered size="small">
          <Descriptions.Item label="Session ID">{session.id}</Descriptions.Item>
          <Descriptions.Item label="User ID">
            {session.user_id}
          </Descriptions.Item>
          <Descriptions.Item label="Status">
            {statusTag(session.status)}
          </Descriptions.Item>
          <Descriptions.Item label="User Agent">
            {session.user_agent || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="IP Address">
            {session.ip_address || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Location">
            {session.location || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Device ID">
            {session.device_id || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Created">
            {formatDate(session.created_at)}
          </Descriptions.Item>
          <Descriptions.Item label="Expires">
            {formatDate(session.expires_at)}
          </Descriptions.Item>
          <Descriptions.Item label="Last Active">
            {formatDate(session.last_activity_at)}
          </Descriptions.Item>
          <Descriptions.Item label="Deactivated">
            {formatDate(session.deactivated_at)}
          </Descriptions.Item>
        </Descriptions>
      )}
    </Drawer>
  );
}

function SessionsView({
  idpSession,
  onBack,
}: {
  idpSession: IdpSessionResponse;
  onBack: () => void;
}) {
  const { message } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });

  const { data, isLoading } = useIdpSessionSessions(
    idpSession.id,
    listParams
  );
  const deactivate = useDeactivateOAuthSession();
  const [detailSession, setDetailSession] =
    useState<OAuthSessionResponse | null>(null);

  const handleDeactivate = async (id: string) => {
    try {
      await deactivate.mutateAsync(id);
      message.success("Session deactivated");
    } catch {
      message.error("Failed to deactivate session");
    }
  };

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter:
        | SorterResult<OAuthSessionResponse>
        | SorterResult<OAuthSessionResponse>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      setListParams((prev) => ({
        ...prev,
        offset:
          ((pagination.current ?? 1) - 1) *
          (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : prev.sort,
        order: s.order === "descend" ? "desc" : "asc",
      }));
    },
    []
  );

  const columns: ColumnsType<OAuthSessionResponse> = [
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
      title: "IP Address",
      dataIndex: "ip_address",
      key: "ip_address",
      width: 140,
      render: (ip: string) => ip || "—",
    },
    {
      title: "Status",
      dataIndex: "status",
      key: "status",
      width: 110,
      render: statusTag,
    },
    {
      title: "Created",
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
      title: "Expires",
      dataIndex: "expires_at",
      key: "expires_at",
      width: 180,
      sorter: true,
      sortOrder:
        listParams.sort === "expires_at"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      render: formatDate,
    },
    {
      title: "Actions",
      key: "actions",
      width: 80,
      render: (_, record) => (
        <Space>
          {record.status === "active" && (
            <Popconfirm
              title="Deactivate this session?"
              onConfirm={() => handleDeactivate(record.id)}
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
          )}
          <Button
            type="text"
            size="small"
            icon={<InfoCircleOutlined />}
            onClick={() => setDetailSession(record)}
          />
        </Space>
      ),
    },
  ];

  return (
    <>
      <Space
        style={{
          justifyContent: "space-between",
          width: "100%",
          flexShrink: 0,
        }}
      >
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={onBack}>
            Back to Sessions
          </Button>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Sessions for {idpSession.username || idpSession.user_id}
          </Typography.Title>
        </Space>
      </Space>

      <Typography.Text
        type="secondary"
        style={{ display: "block", marginTop: 8, flexShrink: 0 }}
      >
        {describeUserAgent(idpSession.user_agent)} — {idpSession.ip_address}
      </Typography.Text>

      <div
        ref={tableContainerRef}
        style={{ flex: 1, overflow: "hidden", marginTop: 16 }}
      >
        <Table<OAuthSessionResponse>
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
            showTotal: (total) => `${total} sessions`,
          }}
          size="small"
        />
      </div>

      <OAuthSessionDetailDrawer
        session={detailSession}
        onClose={() => setDetailSession(null)}
      />
    </>
  );
}

function IdpSessionDetailDrawer({
  session,
  onClose,
}: {
  session: IdpSessionResponse | null;
  onClose: () => void;
}) {
  return (
    <Drawer
      title="Device Session Details"
      open={!!session}
      onClose={onClose}
      width={480}
    >
      {session && (
        <Descriptions column={1} bordered size="small">
          <Descriptions.Item label="Session ID">{session.id}</Descriptions.Item>
          <Descriptions.Item label="User ID">
            {session.user_id}
          </Descriptions.Item>
          <Descriptions.Item label="Username">
            {session.username}
          </Descriptions.Item>
          <Descriptions.Item label="Email">
            {session.email || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="User Agent">
            {session.user_agent || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="IP Address">
            {session.ip_address || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Active Apps">
            {session.active_apps_count}
          </Descriptions.Item>
          <Descriptions.Item label="Last Active">
            {formatDate(session.last_activity_at)}
          </Descriptions.Item>
          <Descriptions.Item label="Signed In">
            {formatDate(session.created_at)}
          </Descriptions.Item>
        </Descriptions>
      )}
    </Drawer>
  );
}

export default function SessionsPage() {
  const { message } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "last_activity_at",
    order: "desc",
  });
  const [searchValue, setSearchValue] = useState("");
  const [dateRange, setDateRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const [dateField, setDateField] = useState<string>("last_activity_at");

  const { data, isLoading, error } = useIdpSessions(listParams);
  const forceLogout = useForceLogoutIdpSession();

  const [sessionsIdp, setSessionsIdp] = useState<IdpSessionResponse | null>(
    null
  );
  const [detailSession, setDetailSession] =
    useState<IdpSessionResponse | null>(null);

  const handleForceLogout = async (id: string) => {
    try {
      await forceLogout.mutateAsync(id);
      message.success("Device signed out");
    } catch {
      message.error("Failed to sign out device");
    }
  };

  const handleDateRange = useCallback(
    (dates: [Dayjs | null, Dayjs | null] | null, field: string) => {
      setDateRange(dates);
      setListParams((prev) => {
        const next: ListParams = { ...prev, offset: 0 };
        delete next.created_at_from;
        delete next.created_at_to;
        delete next.last_activity_at_from;
        delete next.last_activity_at_to;
        if (dates && dates[0]) {
          next[`${field}_from`] = dates[0].startOf("day").toISOString();
        }
        if (dates && dates[1]) {
          next[`${field}_to`] = dates[1].endOf("day").toISOString();
        }
        return next;
      });
    },
    []
  );

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter:
        | SorterResult<IdpSessionResponse>
        | SorterResult<IdpSessionResponse>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      setListParams((prev) => ({
        ...prev,
        offset:
          ((pagination.current ?? 1) - 1) *
          (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : prev.sort,
        order: s.order === "descend" ? "desc" : "asc",
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

  if (sessionsIdp) {
    return (
      <SessionsView
        idpSession={sessionsIdp}
        onBack={() => setSessionsIdp(null)}
      />
    );
  }

  const columns: ColumnsType<IdpSessionResponse> = [
    {
      title: "Session ID",
      dataIndex: "id",
      key: "id",
      width: 140,
      render: (id: string) => (
        <Typography.Text copyable={{ text: id }} style={{ fontSize: 13 }}>
          {id.slice(0, 12) + "..."}
        </Typography.Text>
      ),
    },
    {
      title: "Username",
      dataIndex: "username",
      key: "username",
      width: 140,
      ellipsis: true,
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
      ellipsis: true,
      render: (email: string) => (
        <Typography.Text copyable={{ text: email }} ellipsis>
          {email}
        </Typography.Text>
      ),
    },
    {
      title: "Device",
      key: "device",
      width: 200,
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
      title: "Sessions",
      key: "sessions",
      width: 90,
      render: (_, record) => (
        <Tag color={record.active_apps_count > 0 ? "blue" : "default"}>
          {record.active_apps_count}
        </Tag>
      ),
    },
    {
      title: "Signed In",
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
      title: "Last Active",
      dataIndex: "last_activity_at",
      key: "last_activity_at",
      width: 180,
      sorter: true,
      sortOrder:
        listParams.sort === "last_activity_at"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      render: formatDate,
    },
    {
      title: "Actions",
      key: "actions",
      width: 120,
      render: (_, record) => (
        <Space>
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
          <Button
            type="text"
            size="small"
            icon={<UnorderedListOutlined />}
            onClick={() => setSessionsIdp(record)}
          />
          <Button
            type="text"
            size="small"
            icon={<InfoCircleOutlined />}
            onClick={() => setDetailSession(record)}
          />
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load sessions" />;
  }

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
          Sessions
        </Typography.Title>
        <Space>
          <Select
            value={dateField}
            onChange={(v) => {
              setDateField(v);
              if (dateRange) handleDateRange(dateRange, v);
            }}
            options={[
              { label: "Last Active", value: "last_activity_at" },
              { label: "Signed In", value: "created_at" },
            ]}
            style={{ width: 130 }}
          />
          <DatePicker.RangePicker
            value={dateRange}
            onChange={(dates) => handleDateRange(dates, dateField)}
            allowClear
          />
          <Input.Search
            placeholder="Search username, email, IP..."
            allowClear
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onSearch={handleSearch}
            style={{ width: 250 }}
          />
        </Space>
      </Space>

      <div
        ref={tableContainerRef}
        style={{ flex: 1, overflow: "hidden", marginTop: 16 }}
      >
        <Table<IdpSessionResponse>
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
            showTotal: (total) => `${total} sessions`,
          }}
        />
      </div>

      <IdpSessionDetailDrawer
        session={detailSession}
        onClose={() => setDetailSession(null)}
      />
    </>
  );
}
