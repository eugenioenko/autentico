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

const { Text } = Typography;

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function DeletionRequestsTab() {
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
      message.success("User deleted successfully");
    } catch {
      message.error("Failed to approve deletion");
    }
  };

  const handleCancel = async (id: string) => {
    try {
      await cancel.mutateAsync(id);
      message.success("Request dismissed");
    } catch {
      message.error("Failed to dismiss request");
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
      title: "Username",
      dataIndex: "username",
      key: "username",
      sorter: true,
      ellipsis: true,
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
      sorter: true,
      ellipsis: true,
      render: (email: string) => (
        <Text copyable={{ text: email }} ellipsis>
          {email}
        </Text>
      ),
    },
    {
      title: "Reason",
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
          <Tag>No reason</Tag>
        ),
    },
    {
      title: "Requested",
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
                label: "View details",
                onClick: () => setDetailRequest(record),
              },
              {
                key: "approve",
                label: (
                  <Popconfirm
                    title="Approve deletion?"
                    description="This will permanently delete the user account. This action cannot be undone."
                    onConfirm={() => handleApprove(record.id)}
                    okText="Delete"
                    okButtonProps={{ danger: true }}
                  >
                    <span style={{ color: "#ff4d4f" }}>Approve deletion</span>
                  </Popconfirm>
                ),
              },
              {
                key: "dismiss",
                label: (
                  <Popconfirm
                    title="Dismiss request?"
                    description="The user account will be kept and the request removed."
                    onConfirm={() => handleCancel(record.id)}
                    okText="Dismiss"
                  >
                    <span>Dismiss request</span>
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
          placeholder="Search username, email, or reason..."
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
            showTotal: (total) => `${total} requests`,
          }}
          locale={{ emptyText: "No pending deletion requests" }}
        />
      </div>

      <Drawer
        title="Deletion Request"
        open={!!detailRequest}
        onClose={() => setDetailRequest(null)}
        width={480}
      >
        {detailRequest && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="Username">
              {detailRequest.username}
            </Descriptions.Item>
            <Descriptions.Item label="Email">
              {detailRequest.email}
            </Descriptions.Item>
            <Descriptions.Item label="User ID">
              <Text copyable={{ text: detailRequest.user_id }}>
                {detailRequest.user_id}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="Reason">
              {detailRequest.reason ?? "No reason provided"}
            </Descriptions.Item>
            <Descriptions.Item label="Requested at">
              {formatDate(detailRequest.requested_at)}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </>
  );
}
