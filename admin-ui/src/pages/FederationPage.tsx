import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  Alert,
  Input,
  App,
} from "antd";
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
} from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { FilterValue, SorterResult } from "antd/es/table/interface";
import { useFederationProviders, useDeleteFederationProvider } from "../hooks/useFederation";
import type { FederationProvider } from "../types/federation";
import type { ListParams } from "../api/users";
import FederationCreateForm from "../components/federation/FederationCreateForm";
import FederationEditForm from "../components/federation/FederationEditForm";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";

const { Text } = Typography;

export default function FederationPage() {
  const { message } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "sort_order",
    order: "asc",
  });
  const [searchValue, setSearchValue] = useState("");

  const { data, isLoading, error } = useFederationProviders(listParams);
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

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      filters: Record<string, FilterValue | null>,
      sorter: SorterResult<FederationProvider> | SorterResult<FederationProvider>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      const newParams: ListParams = {
        ...listParams,
        offset:
          ((pagination.current ?? 1) - 1) *
          (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : "sort_order",
        order: s.order === "ascend" ? "asc" : "desc",
      };

      if (filters.enabled?.length) {
        newParams.enabled = filters.enabled[0] as string;
      } else {
        delete newParams.enabled;
      }

      setListParams(newParams);
    },
    [listParams]
  );

  const handleSearch = useCallback((value: string) => {
    setListParams((prev) => ({
      ...prev,
      search: value || undefined,
      offset: 0,
    }));
  }, []);

  const sortOrder = (field: string) =>
    listParams.sort === field
      ? listParams.order === "desc"
        ? ("descend" as const)
        : ("ascend" as const)
      : undefined;

  const columns: ColumnsType<FederationProvider> = [
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
      sorter: true,
      sortOrder: sortOrder("name"),
      ellipsis: true,
      render: (name: string) => (
        <Text copyable={{ text: name }} ellipsis>
          {name}
        </Text>
      ),
    },
    {
      title: "Issuer",
      dataIndex: "issuer",
      key: "issuer",
      sorter: true,
      sortOrder: sortOrder("issuer"),
      ellipsis: true,
      render: (issuer: string) => (
        <Text copyable={{ text: issuer }} ellipsis>
          {issuer}
        </Text>
      ),
    },
    {
      title: "Client ID",
      dataIndex: "client_id",
      key: "client_id",
      sorter: true,
      sortOrder: sortOrder("client_id"),
      ellipsis: true,
      render: (id: string) => (
        <Text copyable={{ text: id }} ellipsis>
          {id}
        </Text>
      ),
    },
    {
      title: "Status",
      dataIndex: "enabled",
      key: "enabled",
      sorter: true,
      sortOrder: sortOrder("enabled"),
      width: 100,
      filters: [
        { text: "Enabled", value: "1" },
        { text: "Disabled", value: "0" },
      ],
      filterMultiple: false,
      render: (enabled: boolean) => (
        <Tag color={enabled ? "success" : "default"}>
          {enabled ? "Enabled" : "Disabled"}
        </Tag>
      ),
    },
    {
      title: "Order",
      dataIndex: "sort_order",
      key: "sort_order",
      sorter: true,
      sortOrder: sortOrder("sort_order"),
      width: 80,
    },
    {
      title: "Actions",
      key: "actions",
      width: 100,
      render: (_, record) => (
        <Space>
          <Popconfirm
            title="Delete this provider?"
            description="Users who signed in via this provider will keep their accounts but won't be able to log in with it again."
            onConfirm={() => handleDelete(record.id)}
            okText="Delete"
            okButtonProps={{ danger: true }}
          >
            <Button type="text" size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
          <Button
            type="text"
            size="small"
            icon={<EditOutlined />}
            onClick={() => setEditProvider(record)}
          />
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load federation providers" />;
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
          Federation Providers
        </Typography.Title>
        <Space>
          <Input.Search
            placeholder="Search name, issuer, or client ID..."
            allowClear
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onSearch={handleSearch}
            style={{ width: 300 }}
          />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            Add Provider
          </Button>
        </Space>
      </Space>

      <div
        ref={tableContainerRef}
        style={{ flex: 1, overflow: "hidden", marginTop: 16 }}
      >
        <Table<FederationProvider>
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
            showTotal: (total) => `${total} providers`,
          }}
        />
      </div>

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
