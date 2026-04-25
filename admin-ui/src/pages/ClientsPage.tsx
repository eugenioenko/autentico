import { useState, useEffect, useCallback, useRef } from "react";
import { useLocation } from "react-router-dom";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Alert,
  Input,
} from "antd";
import {
  PlusOutlined,
  EditOutlined,
  EyeOutlined,
} from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { FilterValue, SorterResult } from "antd/es/table/interface";
import { useClients } from "../hooks/useClients";
import type { ClientInfoResponse } from "../types/client";
import type { ListParams } from "../api/users";
import ClientCreateForm from "../components/clients/ClientCreateForm";
import ClientEditForm from "../components/clients/ClientEditForm";
import ClientDetail from "../components/clients/ClientDetail";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";
import GrantChips from "../components/GrantChips";

const { Text } = Typography;


export default function ClientsPage() {
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });
  const [searchValue, setSearchValue] = useState("");

  const { data, isLoading, error } = useClients(listParams);
  const location = useLocation();

  const [createOpen, setCreateOpen] = useState(false);

  useEffect(() => {
    if ((location.state as { create?: boolean })?.create) {
      setCreateOpen(true);
      window.history.replaceState({}, "");
    }
  }, [location.state]);
  const [editClient, setEditClient] = useState<ClientInfoResponse | null>(null);
  const [detailClient, setDetailClient] =
    useState<ClientInfoResponse | null>(null);

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      filters: Record<string, FilterValue | null>,
      sorter: SorterResult<ClientInfoResponse> | SorterResult<ClientInfoResponse>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      const newParams: ListParams = {
        ...listParams,
        offset:
          ((pagination.current ?? 1) - 1) *
          (pagination.pageSize ?? DEFAULT_PAGE_SIZE),
        limit: pagination.pageSize ?? DEFAULT_PAGE_SIZE,
        sort: s.field ? String(s.field) : "created_at",
        order: s.order === "ascend" ? "asc" : "desc",
      };

      if (filters.client_type?.length) {
        newParams.client_type = filters.client_type[0] as string;
      } else {
        delete newParams.client_type;
      }

      if (filters.is_active?.length) {
        newParams.is_active = filters.is_active[0] as string;
      } else {
        delete newParams.is_active;
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

  const columns: ColumnsType<ClientInfoResponse> = [
    {
      title: "Name",
      dataIndex: "client_name",
      key: "client_name",
      sorter: true,
      sortOrder:
        listParams.sort === "client_name"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      ellipsis: true,
      render: (name: string) => (
        <Text copyable={{ text: name }} ellipsis>
          {name}
        </Text>
      ),
    },
    {
      title: "Client ID",
      dataIndex: "client_id",
      key: "client_id",
      sorter: true,
      sortOrder:
        listParams.sort === "client_id"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      ellipsis: true,
      render: (id: string) => (
        <Text copyable={{ text: id }} ellipsis>
          {id}
        </Text>
      ),
    },
    {
      title: "Type",
      dataIndex: "client_type",
      key: "client_type",
      sorter: true,
      sortOrder:
        listParams.sort === "client_type"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      filters: [
        { text: "Confidential", value: "confidential" },
        { text: "Public", value: "public" },
      ],
      filterMultiple: false,
      render: (type: string) => (
        <Tag color={type === "confidential" ? "blue" : "green"}>{type}</Tag>
      ),
    },
    {
      title: "Grants",
      dataIndex: "grant_types",
      key: "grant_types",
      width: 140,
      render: (types: string[]) => <GrantChips grants={types ?? []} />,
    },
    {
      title: "Status",
      dataIndex: "is_active",
      key: "is_active",
      filters: [
        { text: "Active", value: "1" },
        { text: "Inactive", value: "0" },
      ],
      filterMultiple: false,
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
        </Space>
      ),
    },
  ];

  if (error) {
    return <Alert type="error" message="Failed to load clients" />;
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
          Clients
        </Typography.Title>
        <Space>
          <Input.Search
            placeholder="Search name or client ID..."
            allowClear
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onSearch={handleSearch}
            style={{ width: 280 }}
          />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            Create Client
          </Button>
        </Space>
      </Space>

      <div
        ref={tableContainerRef}
        style={{ flex: 1, overflow: "hidden", marginTop: 16 }}
      >
        <Table<ClientInfoResponse>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey="client_id"
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
            showTotal: (total) => `${total} clients`,
          }}
        />
      </div>

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
