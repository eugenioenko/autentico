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
import CopyText from "../components/CopyText";
import { useTranslation } from "react-i18next";

export default function FederationPage() {
  const { t } = useTranslation();
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
      message.success(t("federation.providerDeleted"));
    } catch {
      message.error(t("federation.deleteProviderFailed"));
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
      title: t("common.name"),
      dataIndex: "name",
      key: "name",
      sorter: true,
      sortOrder: sortOrder("name"),
      ellipsis: true,
      render: (name: string) => (
        <CopyText text={name} />
      ),
    },
    {
      title: t("federation.issuer"),
      dataIndex: "issuer",
      key: "issuer",
      sorter: true,
      sortOrder: sortOrder("issuer"),
      ellipsis: true,
      render: (issuer: string) => (
        <CopyText text={issuer} />
      ),
    },
    {
      title: t("federation.clientIdLabel"),
      dataIndex: "client_id",
      key: "client_id",
      sorter: true,
      sortOrder: sortOrder("client_id"),
      ellipsis: true,
      render: (id: string) => (
        <CopyText text={id} />
      ),
    },
    {
      title: t("common.status"),
      dataIndex: "enabled",
      key: "enabled",
      sorter: true,
      sortOrder: sortOrder("enabled"),
      width: 100,
      filters: [
        { text: t("common.enabled"), value: "1" },
        { text: t("common.disabled"), value: "0" },
      ],
      filterMultiple: false,
      render: (enabled: boolean) => (
        <Tag color={enabled ? "success" : "default"}>
          {enabled ? t("common.enabled") : t("common.disabled")}
        </Tag>
      ),
    },
    {
      title: t("federation.sortOrder"),
      dataIndex: "sort_order",
      key: "sort_order",
      sorter: true,
      sortOrder: sortOrder("sort_order"),
      width: 80,
    },
    {
      title: t("common.actions"),
      key: "actions",
      width: 100,
      render: (_, record) => (
        <Space>
          <Popconfirm
            title={t("federation.deleteProviderConfirm")}
            description={t("federation.deleteProviderDesc")}
            onConfirm={() => handleDelete(record.id)}
            okText={t("common.delete")}
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
    return <Alert type="error" message={t("federation.failedToLoadProviders")} />;
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
          {t("federation.providers")}
        </Typography.Title>
        <Space>
          <Input.Search
            placeholder={t("federation.searchProviders")}
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
            {t("federation.addProvider")}
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
            showTotal: (total) => t("federation.totalProviders", { total }),
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
