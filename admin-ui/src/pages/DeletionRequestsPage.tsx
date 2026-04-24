import { useRef } from "react";
import {
  Typography,
  Table,
  Button,
  Space,
  Popconfirm,
  message,
  Alert,
  Tag,
} from "antd";
import { CheckOutlined, CloseOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import {
  useDeletionRequests,
  useApproveDeletionRequest,
  useAdminCancelDeletionRequest,
} from "../hooks/useDeletionRequests";
import type { DeletionRequestResponse } from "../api/deletion";
import { useTableScrollY } from "../hooks/useTableScrollY";

function formatDate(date: string): string {
  return new Date(date).toLocaleString();
}

export default function DeletionRequestsPage() {
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);
  const { data: requests, isLoading, error } = useDeletionRequests();
  const approve = useApproveDeletionRequest();
  const cancel = useAdminCancelDeletionRequest();

  const handleApprove = async (id: string) => {
    try {
      await approve.mutateAsync(id);
      message.success("User deleted");
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

  const columns: ColumnsType<DeletionRequestResponse> = [
    {
      title: "User ID",
      dataIndex: "user_id",
      key: "user_id",
      ellipsis: true,
    },
    {
      title: "Reason",
      dataIndex: "reason",
      key: "reason",
      render: (reason?: string) =>
        reason ? <span>{reason}</span> : <Tag>No reason</Tag>,
    },
    {
      title: "Requested At",
      dataIndex: "requested_at",
      key: "requested_at",
      render: formatDate,
    },
    {
      title: "Actions",
      key: "actions",
      render: (_, record) => (
        <Space>
          <Popconfirm
            title="Approve deletion?"
            description="This will permanently delete the user account. This action cannot be undone."
            onConfirm={() => handleApprove(record.id)}
            okText="Delete"
            okButtonProps={{ danger: true }}
          >
            <Button
              type="text"
              size="small"
              danger
              icon={<CheckOutlined />}
            >
              Approve
            </Button>
          </Popconfirm>
          <Popconfirm
            title="Dismiss request?"
            description="The user account will be kept and the request removed."
            onConfirm={() => handleCancel(record.id)}
            okText="Dismiss"
          >
            <Button type="text" size="small" icon={<CloseOutlined />}>
              Dismiss
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load deletion requests" />;
  }

  return (
    <>
      <Space style={{ justifyContent: "space-between", width: "100%", flexShrink: 0 }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Deletion Requests
          </Typography.Title>
          <Typography.Text type="secondary">
            Review and approve or dismiss pending account deletion requests.
          </Typography.Text>
        </div>
      </Space>

      <div ref={tableContainerRef} style={{ flex: 1, overflow: "hidden", marginTop: 16 }}>
        <Table<DeletionRequestResponse>
          columns={columns}
          dataSource={requests ?? []}
          rowKey="id"
          loading={isLoading}
          scroll={scrollY ? { y: scrollY } : undefined}
          pagination={{ pageSize: 20 }}
          locale={{ emptyText: "No pending deletion requests" }}
        />
      </div>
    </>
  );
}
