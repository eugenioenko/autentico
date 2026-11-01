import {
  createColumnHelper,
  createPaginatedRowModel,
  createSortedRowModel,
  functionalUpdate,
  rowPaginationFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_basic,
  sortFn_datetime,
  tableFeatures,
  useTable,
  type CellData,
  type ColumnDef,
  type OnChangeFn,
  type RowData,
  type SortingState,
  type TableFeatures,
} from "@tanstack/react-table";
import { EmptyState, Inline, Pagination, Select, Skeleton, Stack, Table, Text, type CellAlign } from "@yarcl/react";
import { useRef, useState, type ReactNode } from "react";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";
import type { ListParams } from "../api/users";
import { useFillHeight } from "../hooks/useFillHeight";
import "./DataTable.css";

declare module "@tanstack/react-table" {
  interface ColumnMeta<TFeatures extends TableFeatures, TData extends RowData, TValue extends CellData = CellData> {
    align?: CellAlign;
    width?: number | string;
  }
}

export const features = tableFeatures({
  rowSortingFeature,
  rowPaginationFeature,
  sortedRowModel: createSortedRowModel(),
  paginatedRowModel: createPaginatedRowModel(),
  sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic, datetime: sortFn_datetime },
});

export type DataFeatures = typeof features;

export function dataColumns<T extends object>() {
  return createColumnHelper<DataFeatures, T>();
}

export interface DataFilter {
  key: string;
  label: string;
  allLabel?: string;
  options: { value: string; label: string }[];
}

export interface ServerList {
  params: ListParams;
  onParamsChange: (params: ListParams) => void;
  total: number;
  totalLabel?: (total: number) => string;
}

type DataTableProps<T extends object> = {
  data: T[];
  columns: ColumnDef<DataFeatures, T, any>[];
  caption: string;
  getRowId?: (row: T) => string;
  loading?: boolean;
  emptyTitle?: string;
  emptyDescription?: ReactNode;
  filters?: DataFilter[];
  toolbar?: ReactNode;
  onRowClick?: (row: T) => void;
} & ({ server?: undefined; pageSize?: number | false } | { server: ServerList });

const ALL = "__all__";

function serverOptions({ params, onParamsChange }: ServerList) {
  const sorting: SortingState = params.sort ? [{ id: params.sort, desc: params.order !== "asc" }] : [];
  const onSortingChange: OnChangeFn<SortingState> = (updater) => {
    const next = functionalUpdate(updater, sorting)[0];
    onParamsChange({ ...params, offset: 0, sort: next?.id, order: next ? (next.desc ? "desc" : "asc") : undefined });
  };
  return {
    manualSorting: true,
    manualPagination: true,
    enableMultiSort: false,
    state: { sorting },
    onSortingChange,
  };
}

export function DataTable<T extends object>(props: DataTableProps<T>) {
  const { data, columns, caption, getRowId, loading, emptyTitle = "No data", emptyDescription, filters = [], toolbar, onRowClick } = props;
  const server = props.server ?? null;
  const clientPageSize = props.server ? false : props.pageSize ?? DEFAULT_PAGE_SIZE;
  const [clientFilters, setClientFilters] = useState<Record<string, string | undefined>>({});

  const filterValues: Record<string, string | undefined> = server
    ? Object.fromEntries(filters.map((f) => [f.key, server.params[f.key] as string | undefined]))
    : clientFilters;
  const setFilter = (key: string, value: string | undefined) => {
    if (server) server.onParamsChange({ ...server.params, offset: 0, [key]: value });
    else setClientFilters((prev) => ({ ...prev, [key]: value }));
  };
  const rowsData = server
    ? data
    : data.filter((row) =>
        Object.entries(clientFilters).every(([key, value]) => value === undefined || String((row as Record<string, unknown>)[key]) === value),
      );

  const table = useTable({
    features,
    columns,
    data: rowsData,
    getRowId,
    initialState: { pagination: { pageIndex: 0, pageSize: clientPageSize || Math.max(rowsData.length, 1) } },
    ...(server ? serverOptions(server) : {}),
  });

  const rows = server || clientPageSize ? table.getRowModel().rows : table.getPrePaginatedRowModel().rows;
  const pageSize = server ? server.params.limit ?? DEFAULT_PAGE_SIZE : clientPageSize || rows.length;
  const page = server ? Math.floor((server.params.offset ?? 0) / pageSize) + 1 : table.state.pagination.pageIndex + 1;
  const total = server ? server.total : rowsData.length;
  const pageCount = Math.max(1, Math.ceil(total / Math.max(pageSize, 1)));
  const setPage = (next: number) => {
    if (server) server.onParamsChange({ ...server.params, offset: (next - 1) * pageSize });
    else table.setPageIndex(next - 1);
  };

  const frameRef = useRef<HTMLDivElement>(null);
  const footerRef = useRef<HTMLDivElement>(null);
  const maxHeight = useFillHeight(frameRef, footerRef, [rows.length, total > 0, filters.length]);

  const showToolbar = filters.length > 0 || toolbar;
  return (
    <Stack gap="sm" className="data-table">
      {showToolbar && (
        <Inline gap="sm" align="end">
          {filters.map((f) => (
            <Select
              key={f.key}
              aria-label={f.label}
              options={[{ value: ALL, label: f.allLabel ?? `All ${f.label.toLowerCase()}` }, ...f.options]}
              value={filterValues[f.key] ?? ALL}
              onValueChange={(v) => setFilter(f.key, !v || v === ALL ? undefined : v)}
            />
          ))}
          {toolbar}
        </Inline>
      )}
      <div ref={frameRef} className="data-table-frame" data-loading={loading && rows.length > 0 ? "" : undefined} aria-busy={loading || undefined}>
        <Table aria-label={caption} interactive={!!onRowClick} stickyHeader wrapStyle={maxHeight ? { maxHeight } : undefined}>
          <Table.Head>
            {table.getHeaderGroups().map((group) => (
              <Table.Row key={group.id}>
                {group.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  const meta = header.column.columnDef.meta;
                  return (
                    <Table.HeaderCell
                      key={header.id}
                      align={meta?.align}
                      style={meta?.width !== undefined ? { width: meta.width } : undefined}
                      sortable={header.column.getCanSort()}
                      sortDirection={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none"}
                      onSort={(direction) => header.column.toggleSorting(direction === "descending")}
                    >
                      {header.isPlaceholder ? null : <table.FlexRender header={header} />}
                    </Table.HeaderCell>
                  );
                })}
              </Table.Row>
            ))}
          </Table.Head>
          <Table.Body>
            {loading && rows.length === 0
              ? Array.from({ length: 3 }, (_, i) => (
                  <Table.Row key={`skeleton-${i}`}>
                    {columns.map((_, j) => (
                      <Table.Cell key={j}>
                        <Skeleton shape="text" />
                      </Table.Cell>
                    ))}
                  </Table.Row>
                ))
              : rows.map((row) => (
                  <Table.Row
                    key={row.id}
                    onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                    className={onRowClick ? "data-table-clickable" : undefined}
                  >
                    {row.getAllCells().map((cell) => (
                      <Table.Cell key={cell.id} align={cell.column.columnDef.meta?.align}>
                        <table.FlexRender cell={cell} />
                      </Table.Cell>
                    ))}
                  </Table.Row>
                ))}
          </Table.Body>
        </Table>
        {!loading && rows.length === 0 && <EmptyState title={emptyTitle} description={emptyDescription} headingLevel={3} />}
      </div>
      {(server || clientPageSize) && total > 0 && (
        <Inline ref={footerRef} gap="md" justify="between" align="center">
          <Text textStyle="caption" muted>
            {server?.totalLabel ? server.totalLabel(total) : `${total} total`}
          </Text>
          <Inline gap="sm" align="center">
            {pageCount > 1 && <Pagination count={pageCount} page={page} onPageChange={setPage} aria-label={`${caption} pages`} />}
            {server && (
              <Select
                aria-label="Rows per page"
                options={PAGE_SIZE_OPTIONS.map((n) => ({ value: String(n), label: `${n} / page` }))}
                value={String(pageSize)}
                onValueChange={(v) => v && server.onParamsChange({ ...server.params, offset: 0, limit: Number(v) })}
              />
            )}
          </Inline>
        </Inline>
      )}
    </Stack>
  );
}
