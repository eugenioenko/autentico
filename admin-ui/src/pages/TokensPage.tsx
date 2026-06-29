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
import GrantChips from "../components/GrantChips";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";
import CopyText from "../components/CopyText";
import { useTranslation } from "react-i18next";

function formatDate(date: string | null): string {
  if (!date) return "\u2014";
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
  const { t } = useTranslation();
  return (
    <Drawer title={t("tokens.tokenDetail")} open={!!token} onClose={onClose} width={480}>
      {token && (
        <Descriptions column={1} bordered size="small">
          <Descriptions.Item label={t("tokens.tokenId")}>{token.id}</Descriptions.Item>
          <Descriptions.Item label={t("common.status")}>
            {statusTag(token.status)}
          </Descriptions.Item>
          <Descriptions.Item label={t("sessions.userId")}>
            {token.user_id || "\u2014"}
          </Descriptions.Item>
          <Descriptions.Item label={t("users.username")}>
            {token.username || "\u2014"}
          </Descriptions.Item>
          <Descriptions.Item label={t("users.email")}>
            {token.email || "\u2014"}
          </Descriptions.Item>
          <Descriptions.Item label={t("clients.grantType")}>
            <GrantChips grants={[token.grant_type]} />
          </Descriptions.Item>
          <Descriptions.Item label={t("clients.scope")}>
            {token.scope || "\u2014"}
          </Descriptions.Item>
          <Descriptions.Item label={t("tokens.issuedAt")}>
            {formatDate(token.issued_at)}
          </Descriptions.Item>
          <Descriptions.Item label={t("tokens.accessTokenExpires")}>
            {formatDate(token.access_token_expires_at)}
          </Descriptions.Item>
          <Descriptions.Item label={t("tokens.revokedAt")}>
            {formatDate(token.revoked_at)}
          </Descriptions.Item>
        </Descriptions>
      )}
    </Drawer>
  );
}

export default function TokensPage() {
  const { t } = useTranslation();
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
      message.success(t("tokens.tokenRevoked"));
    } catch {
      message.error(t("tokens.revokeTokenFailed"));
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
      title: t("tokens.tokenId"),
      dataIndex: "id",
      key: "id",
      width: 140,
      render: (id: string) => (
        <CopyText text={id}>{id.slice(0, 12) + "..."}</CopyText>
      ),
    },
    {
      title: t("users.username"),
      dataIndex: "username",
      key: "username",
      width: 140,
      ellipsis: true,
      render: (username: string) => username || "\u2014",
    },
    {
      title: t("users.email"),
      dataIndex: "email",
      key: "email",
      ellipsis: true,
      render: (email: string) =>
        email ? (
          <CopyText text={email} />
        ) : (
          "\u2014"
        ),
    },
    {
      title: t("clients.grantType"),
      dataIndex: "grant_type",
      key: "grant_type",
      width: 100,
      render: (grant: string) => <GrantChips grants={[grant]} />,
    },
    {
      title: t("common.status"),
      dataIndex: "status",
      key: "status",
      width: 100,
      render: statusTag,
    },
    {
      title: t("common.expires"),
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
      title: t("tokens.issuedAt"),
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
      title: t("common.actions"),
      key: "actions",
      width: 80,
      render: (_, record) => (
        <Space>
          {record.status === "active" && (
            <Popconfirm
              title={t("tokens.revokeToken")}
              onConfirm={() => handleRevoke(record.id)}
              okText={t("tokens.revokeAction")}
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
    return <Alert type="error" message={t("tokens.failedToLoadTokens")} />;
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
          {t("tokens.title")}
        </Typography.Title>
        <Space>
          <DatePicker.RangePicker
            value={dateRange}
            onChange={(dates) => handleDateRange(dates)}
            allowClear
          />
          <Input.Search
            placeholder={t("tokens.searchTokens")}
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
            showTotal: (total) => t("tokens.totalTokens", { total }),
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
