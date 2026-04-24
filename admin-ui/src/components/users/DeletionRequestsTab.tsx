import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Tag,
  Popconfirm,
  message,
  Dropdown,
  Drawer,
  Descriptions,
  Input,
} from "antd";
import { MoreOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import {
  useDeletionRequests,
  useApproveDeletionRequest,
  useAdminCancelDeletionRequest,
} from "../../hooks/useDeletionRequests";
import type { DeletionRequestResponse } from "../../api/deletion";
import { useTableScrollY } from "../../hooks/useTableScrollY";

const { Text } = Typography;

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function DeletionRequestsTab() {
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);
  const { data: requests, isLoading } = useDeletionRequests();
  const approve = useApproveDeletionRequest();
  const cancel = useAdminCancelDeletionRequest();

  const [detailRequest, setDetailRequest] =
    useState<DeletionRequestResponse | null>(null);
  const [searchValue, setSearchValue] = useState("");
  const [searchFilter, setSearchFilter] = useState("");

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
    setSearchFilter(value.toLowerCase());
  }, []);

  const filtered = (requests ?? []).filter((r) => {
    if (!searchFilter) return true;
    return (
      r.username?.toLowerCase().includes(searchFilter) ||
      r.email?.toLowerCase().includes(searchFilter) ||
      r.reason?.toLowerCase().includes(searchFilter)
    );
  });

  const columns: ColumnsType<DeletionRequestResponse> = [
    {
      title: "Username",
      dataIndex: "username",
      key: "username",
      ellipsis: true,
      sorter: (a, b) => (a.username ?? "").localeCompare(b.username ?? ""),
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
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
      sorter: (a, b) =>
        new Date(a.requested_at).getTime() -
        new Date(b.requested_at).getTime(),
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

      <div
        ref={tableContainerRef}
        style={{ flex: 1, overflow: "hidden" }}
      >
        <Table<DeletionRequestResponse>
          columns={columns}
          dataSource={filtered}
          rowKey="id"
          loading={isLoading}
          scroll={scrollY ? { y: scrollY } : undefined}
          pagination={{ pageSize: 20, showTotal: (total) => `${total} requests` }}
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
