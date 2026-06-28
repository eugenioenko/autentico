import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Tag,
  Popconfirm,
  Dropdown,
  Drawer,
  Descriptions,
  Input,
  App,
} from "antd";
import { MoreOutlined } from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { SorterResult } from "antd/es/table/interface";
import {
  useDeletionRequests,
  useApproveDeletionRequest,
  useAdminCancelDeletionRequest,
} from "../../hooks/useDeletionRequests";
import type { DeletionRequestResponse } from "../../api/deletion";
import type { ListParams } from "../../api/users";
import { useTableScrollY } from "../../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../../constants/table";
import CopyText from "../CopyText";
import { useTranslation } from "react-i18next";

const { Text } = Typography;

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function DeletionRequestsTab() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "requested_at",
    order: "asc",
  });
  const [searchValue, setSearchValue] = useState("");

  const { data, isLoading } = useDeletionRequests(listParams);
  const approve = useApproveDeletionRequest();
  const cancel = useAdminCancelDeletionRequest();

  const [detailRequest, setDetailRequest] =
    useState<DeletionRequestResponse | null>(null);

  const handleApprove = async (id: string) => {
    try {
      await approve.mutateAsync(id);
      message.success(t("users.userDeletedSuccess"));
    } catch {
      message.error(t("users.approveFailed"));
    }
  };

  const handleCancel = async (id: string) => {
    try {
      await cancel.mutateAsync(id);
      message.success(t("users.requestDismissed"));
    } catch {
      message.error(t("users.dismissFailed"));
    }
  };

  const handleSearch = useCallback((value: string) => {
    setListParams((prev) => ({
      ...prev,
      search: value || undefined,
      offset: 0,
    }));
  }, []);

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter:
        | SorterResult<DeletionRequestResponse>
        | SorterResult<DeletionRequestResponse>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      setListParams((prev) => ({
        ...prev,
        offset:
          ((pagination.current ?? 1) - 1) *
          (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : "requested_at",
        order: s.order === "ascend" ? "asc" : "desc",
      }));
    },
    []
  );

  const columns: ColumnsType<DeletionRequestResponse> = [
    {
      title: t("users.username"),
      dataIndex: "username",
      key: "username",
      sorter: true,
      ellipsis: true,
    },
    {
      title: t("users.email"),
      dataIndex: "email",
      key: "email",
      sorter: true,
      ellipsis: true,
      render: (email: string) => (
        <CopyText text={email} />
      ),
    },
    {
      title: t("common.reason"),
      dataIndex: "reason",
      key: "reason",
      ellipsis: true,
      width: 250,
      render: (reason?: string) =>
        reason ? (
          <Text ellipsis style={{ maxWidth: 220 }}>
            {reason}
          </Text>
        ) : (
          <Tag>{t("users.noReason")}</Tag>
        ),
    },
    {
      title: t("users.requestedAt"),
      dataIndex: "requested_at",
      key: "requested_at",
      sorter: true,
      defaultSortOrder: "ascend",
      render: formatDate,
    },
    {
      title: "",
      key: "actions",
      width: 50,
      render: (_, record) => (
        <Dropdown
          menu={{
            items: [
              {
                key: "view",
                label: t("users.viewDetails"),
                onClick: () => setDetailRequest(record),
              },
              {
                key: "approve",
                label: (
                  <Popconfirm
                    title={t("users.approveDeletion")}
                    description={t("users.approveDeletionDesc")}
                    onConfirm={() => handleApprove(record.id)}
                    okText={t("users.approveAction")}
                    okButtonProps={{ danger: true }}
                  >
                    <span style={{ color: "#ff4d4f" }}>{t("users.approveDeletionAction")}</span>
                  </Popconfirm>
                ),
              },
              {
                key: "dismiss",
                label: (
                  <Popconfirm
                    title={t("users.dismissRequest")}
                    description={t("users.dismissRequestDesc")}
                    onConfirm={() => handleCancel(record.id)}
                    okText={t("users.dismissAction")}
                  >
                    <span>{t("users.dismissRequestAction")}</span>
                  </Popconfirm>
                ),
              },
            ],
          }}
          trigger={["click"]}
        >
          <MoreOutlined style={{ fontSize: 16, cursor: "pointer" }} />
        </Dropdown>
      ),
    },
  ];

  return (
    <>
      <div style={{ marginBottom: 16, flexShrink: 0 }}>
        <Input.Search
          placeholder={t("users.searchDeletionRequests")}
          allowClear
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          onSearch={handleSearch}
          style={{ width: 320 }}
        />
      </div>

      <div ref={tableContainerRef} style={{ flex: 1, overflow: "hidden" }}>
        <Table<DeletionRequestResponse>
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
            showTotal: (total) => t("users.totalRequests", { total }),
          }}
          locale={{ emptyText: t("users.noPendingDeletionRequests") }}
        />
      </div>

      <Drawer
        title={t("users.deletionRequest")}
        open={!!detailRequest}
        onClose={() => setDetailRequest(null)}
        width={480}
      >
        {detailRequest && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label={t("users.username")}>
              {detailRequest.username}
            </Descriptions.Item>
            <Descriptions.Item label={t("users.email")}>
              {detailRequest.email}
            </Descriptions.Item>
            <Descriptions.Item label={t("sessions.userId")}>
              <CopyText text={detailRequest.user_id} />
            </Descriptions.Item>
            <Descriptions.Item label={t("common.reason")}>
              {detailRequest.reason ?? t("users.noReasonProvided")}
            </Descriptions.Item>
            <Descriptions.Item label={t("users.requestedAt")}>
              {formatDate(detailRequest.requested_at)}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </>
  );
}
