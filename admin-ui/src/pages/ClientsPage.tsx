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
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  EyeOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useClients, useDeleteClient } from "../hooks/useClients";
import type { ClientInfoResponse } from "../types/client";
import ClientCreateForm from "../components/clients/ClientCreateForm";
import ClientEditForm from "../components/clients/ClientEditForm";
import ClientDetail from "../components/clients/ClientDetail";

export default function ClientsPage() {
  const { data: clients, isLoading, error } = useClients();
  const deleteClient = useDeleteClient();

  const [createOpen, setCreateOpen] = useState(false);
  const [editClient, setEditClient] = useState<ClientInfoResponse | null>(null);
  const [detailClient, setDetailClient] =
    useState<ClientInfoResponse | null>(null);

  const handleDelete = async (clientId: string) => {
    try {
      await deleteClient.mutateAsync(clientId);
      message.success("Client deactivated");
    } catch {
      message.error("Failed to deactivate client");
    }
  };

  const columns: ColumnsType<ClientInfoResponse> = [
    {
      title: "Name",
      dataIndex: "client_name",
      key: "client_name",
    },
    {
      title: "Client ID",
      dataIndex: "client_id",
      key: "client_id",
      ellipsis: true,
    },
    {
      title: "Type",
      dataIndex: "client_type",
      key: "client_type",
      render: (type: string) => (
        <Tag color={type === "confidential" ? "blue" : "green"}>{type}</Tag>
      ),
    },
    {
      title: "Grant Types",
      dataIndex: "grant_types",
      key: "grant_types",
      render: (types: string[]) => (
        <Space size={[0, 4]} wrap>
          {types?.map((t) => (
            <Tag key={t}>{t}</Tag>
          ))}
        </Space>
      ),
    },
    {
      title: "Status",
      dataIndex: "is_active",
      key: "is_active",
      render: (active: boolean) => (
        <Tag color={active ? "success" : "error"}>
          {active ? "Active" : "Inactive"}
        </Tag>
      ),
    },
    {
      title: "Actions",
      key: "actions",
      render: (_, record) => (
        <Space>
          <Button
            type="text"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => setDetailClient(record)}
          />
          <Button
            type="text"
            size="small"
            icon={<EditOutlined />}
            onClick={() => setEditClient(record)}
          />
          {record.is_active && (
            <Popconfirm
              title="Deactivate this client?"
              description="The client will no longer be able to authenticate."
              onConfirm={() => handleDelete(record.client_id!)}
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
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load clients" />;
  }

  return (
    <>
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <Space style={{ justifyContent: "space-between", width: "100%" }}>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Clients
          </Typography.Title>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            Create Client
          </Button>
        </Space>

        <Table<ClientInfoResponse>
          columns={columns}
          dataSource={clients ?? []}
          rowKey="client_id"
          loading={isLoading}
          pagination={false}
        />
      </Space>

      <ClientCreateForm
        open={createOpen}
        onClose={() => setCreateOpen(false)}
      />

      <ClientEditForm
        open={!!editClient}
        client={editClient}
        onClose={() => setEditClient(null)}
      />

      <ClientDetail
        open={!!detailClient}
        client={detailClient}
        onClose={() => setDetailClient(null)}
      />
    </>
  );
}
