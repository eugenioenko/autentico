import { useState } from "react";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  message,
  Alert,
} from "antd";
import { PlusOutlined, EditOutlined, DeleteOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useFederationProviders, useDeleteFederationProvider } from "../hooks/useFederation";
import type { FederationProvider } from "../types/federation";
import FederationCreateForm from "../components/federation/FederationCreateForm";
import FederationEditForm from "../components/federation/FederationEditForm";

export default function FederationPage() {
  const { data: providers, isLoading, error } = useFederationProviders();
  const deleteProvider = useDeleteFederationProvider();

  const [createOpen, setCreateOpen] = useState(false);
  const [editProvider, setEditProvider] = useState<FederationProvider | null>(null);

  const handleDelete = async (id: string) => {
    try {
      await deleteProvider.mutateAsync(id);
      message.success("Provider deleted");
    } catch {
      message.error("Failed to delete provider");
    }
  };

  const columns: ColumnsType<FederationProvider> = [
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
    },
    {
      title: "Issuer",
      dataIndex: "issuer",
      key: "issuer",
      ellipsis: true,
    },
    {
      title: "Client ID",
      dataIndex: "client_id",
      key: "client_id",
      ellipsis: true,
    },
    {
      title: "Order",
      dataIndex: "sort_order",
      key: "sort_order",
      width: 80,
    },
    {
      title: "Status",
      dataIndex: "enabled",
      key: "enabled",
      width: 100,
      render: (enabled: boolean) => (
        <Tag color={enabled ? "success" : "default"}>
          {enabled ? "Enabled" : "Disabled"}
        </Tag>
      ),
    },
    {
      title: "Actions",
      key: "actions",
      width: 100,
      render: (_, record) => (
        <Space>
          <Button
            type="text"
            size="small"
            icon={<EditOutlined />}
            onClick={() => setEditProvider(record)}
          />
          <Popconfirm
            title="Delete this provider?"
            description="Users who signed in via this provider will keep their accounts but won't be able to log in with it again."
            onConfirm={() => handleDelete(record.id)}
            okText="Delete"
            okButtonProps={{ danger: true }}
          >
            <Button type="text" size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load federation providers" />;
  }

  return (
    <>
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <Space style={{ justifyContent: "space-between", width: "100%" }}>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Federation Providers
          </Typography.Title>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            Add Provider
          </Button>
        </Space>

        <Table<FederationProvider>
          columns={columns}
          dataSource={providers ?? []}
          rowKey="id"
          loading={isLoading}
          pagination={false}
        />
      </Space>

      <FederationCreateForm
        open={createOpen}
        onClose={() => setCreateOpen(false)}
      />

      <FederationEditForm
        open={!!editProvider}
        provider={editProvider}
        onClose={() => setEditProvider(null)}
      />
    </>
  );
}
