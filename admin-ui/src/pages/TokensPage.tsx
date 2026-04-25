import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  Input,
  Drawer,
  Descriptions,
  DatePicker,
  Alert,
  App,
} from "antd";
import { DeleteOutlined, InfoCircleOutlined } from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { SorterResult } from "antd/es/table/interface";
import type { Dayjs } from "dayjs";
import { useTokens, useRevokeToken } from "../hooks/useTokens";
import type { ListParams } from "../api/users";
import type { AdminTokenResponse } from "../types/token";
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

function TokenDetailDrawer({
  token,
  onClose,
}: {
  token: AdminTokenResponse | null;
  onClose: () => void;
}) {
  return (
    <Drawer title="Token Details" open={!!token} onClose={onClose} width={480}>
      {token && (
        <Descriptions column={1} bordered size="small">
          <Descriptions.Item label="Token ID">{token.id}</Descriptions.Item>
          <Descriptions.Item label="Status">
            {statusTag(token.status)}
          </Descriptions.Item>
          <Descriptions.Item label="User ID">
            {token.user_id || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Username">
            {token.username || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Email">
            {token.email || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Grant Type">
            {token.grant_type}
          </Descriptions.Item>
          <Descriptions.Item label="Scope">
            {token.scope || "—"}
          </Descriptions.Item>
          <Descriptions.Item label="Issued At">
            {formatDate(token.issued_at)}
          </Descriptions.Item>
          <Descriptions.Item label="Access Token Expires">
            {formatDate(token.access_token_expires_at)}
          </Descriptions.Item>
          <Descriptions.Item label="Revoked At">
            {formatDate(token.revoked_at)}
          </Descriptions.Item>
        </Descriptions>
      )}
    </Drawer>
  );
}

export default function TokensPage() {
  const { message } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "issued_at",
    order: "desc",
  });
  const [searchValue, setSearchValue] = useState("");
  const [dateRange, setDateRange] = useState<
    [Dayjs | null, Dayjs | null] | null
  >(null);

  const { data, isLoading, error } = useTokens(listParams);
  const revoke = useRevokeToken();
  const [detailToken, setDetailToken] = useState<AdminTokenResponse | null>(
    null
  );

  const handleRevoke = async (id: string) => {
    try {
      await revoke.mutateAsync(id);
      message.success("Token revoked");
    } catch {
      message.error("Failed to revoke token");
    }
  };

  const handleDateRange = useCallback(
    (dates: [Dayjs | null, Dayjs | null] | null) => {
      setDateRange(dates);
      setListParams((prev) => {
        const next: ListParams = { ...prev, offset: 0 };
        delete next.issued_at_from;
        delete next.issued_at_to;
        if (dates && dates[0]) {
          next.issued_at_from = dates[0].startOf("day").toISOString();
        }
        if (dates && dates[1]) {
          next.issued_at_to = dates[1].endOf("day").toISOString();
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
        | SorterResult<AdminTokenResponse>
        | SorterResult<AdminTokenResponse>[]
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

  const columns: ColumnsType<AdminTokenResponse> = [
    {
      title: "Token ID",
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
      render: (username: string) => username || "—",
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
      ellipsis: true,
      render: (email: string) =>
        email ? (
          <Typography.Text copyable={{ text: email }} ellipsis>
            {email}
          </Typography.Text>
        ) : (
          "—"
        ),
    },
    {
      title: "Grant Type",
      dataIndex: "grant_type",
      key: "grant_type",
      width: 150,
    },
    {
      title: "Status",
      dataIndex: "status",
      key: "status",
      width: 100,
      render: statusTag,
    },
    {
      title: "Expires",
      dataIndex: "access_token_expires_at",
      key: "access_token_expires_at",
      width: 180,
      sorter: true,
      sortOrder:
        listParams.sort === "access_token_expires_at"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      render: formatDate,
    },
    {
      title: "Issued At",
      dataIndex: "issued_at",
      key: "issued_at",
      width: 180,
      sorter: true,
      sortOrder:
        listParams.sort === "issued_at"
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
              title="Revoke this token?"
              onConfirm={() => handleRevoke(record.id)}
              okText="Revoke"
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
            onClick={() => setDetailToken(record)}
          />
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load tokens" />;
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
          Tokens
        </Typography.Title>
        <Space>
          <DatePicker.RangePicker
            value={dateRange}
            onChange={(dates) => handleDateRange(dates)}
            allowClear
          />
          <Input.Search
            placeholder="Search username, email..."
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
        <Table<AdminTokenResponse>
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
            showTotal: (total) => `${total} tokens`,
          }}
          size="small"
        />
      </div>

      <TokenDetailDrawer
        token={detailToken}
        onClose={() => setDetailToken(null)}
      />
    </>
  );
}
