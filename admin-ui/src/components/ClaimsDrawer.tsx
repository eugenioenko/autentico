import { useState, type ReactNode } from "react";
import {
  Drawer,
  Input,
  Table,
  Button,
  Space,
  Typography,
  Popconfirm,
  Tooltip,
  App,
} from "antd";
import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { UserClaim as CustomClaim } from "../types/userClaim";

interface ClaimsDrawerProps {
  open: boolean;
  title: string;
  description: ReactNode;
  claims: CustomClaim[];
  isLoading: boolean;
  isSaving: boolean;
  error?: boolean;
  prefix?: string;
  onSave: (name: string, value: string) => Promise<void>;
  onRemove: (name: string) => Promise<void>;
  onClose: () => void;
}

export default function ClaimsDrawer({
  open,
  title,
  description,
  claims,
  isLoading,
  isSaving,
  error,
  prefix,
  onSave,
  onRemove,
  onClose,
}: ClaimsDrawerProps) {
  const { message } = App.useApp();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");

  const reset = () => {
    setName("");
    setValue("");
  };

  const handleAdd = async () => {
    if (!name.trim()) return;
    try {
      await onSave(name.trim(), value);
      message.success("Claim saved");
      reset();
    } catch (err) {
      const detail =
        (err as { response?: { data?: { error_description?: string } } })
          ?.response?.data?.error_description ?? "Failed to save claim";
      message.error(detail);
    }
  };

  const handleDelete = async (claimName: string) => {
    try {
      await onRemove(claimName);
      message.success("Claim removed");
    } catch {
      message.error("Failed to remove claim");
    }
  };

  const columns: ColumnsType<CustomClaim> = [
    {
      title: prefix ? "Emitted name" : "Name",
      dataIndex: "name",
      key: "name",
      ellipsis: true,
      render: (claimName: string) => prefix ? `${prefix}.${claimName}` : claimName,
    },
    { title: "Value", dataIndex: "value", key: "value", ellipsis: true },
    {
      title: "",
      key: "actions",
      width: 50,
      render: (_, record) => (
        <Tooltip title="Remove claim">
          <Popconfirm
            title="Remove this claim?"
            onConfirm={() => handleDelete(record.name)}
            okText="Remove"
            okButtonProps={{ danger: true }}
          >
            <Button
              type="text"
              size="small"
              danger
              aria-label={`Remove claim ${record.name}`}
              icon={<DeleteOutlined />}
            />
          </Popconfirm>
        </Tooltip>
      ),
    },
  ];

  return (
    <Drawer
      title={title}
      open={open}
      onClose={() => {
        onClose();
        reset();
      }}
      width={560}
    >
      <Space direction="vertical" size="middle" style={{ display: "flex" }}>
        <div>
          <Typography.Text
            type="secondary"
            style={{ display: "block", marginBottom: 8 }}
          >
            Add claim
          </Typography.Text>
          <Space.Compact style={{ width: "100%" }}>
            <Input
              style={{ width: "40%" }}
              aria-label="Claim name"
              placeholder="name"
              maxLength={prefix ? 128 : 229}
              value={name}
              onChange={(e) => setName(e.target.value)}
              onPressEnter={handleAdd}
            />
            <Input
              style={{ width: "60%" }}
              aria-label="Claim value"
              placeholder="value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onPressEnter={handleAdd}
            />
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleAdd}
              loading={isSaving}
              disabled={!name.trim()}
            >
              Add
            </Button>
          </Space.Compact>
          <Typography.Text
            type="secondary"
            style={{ display: "block", marginTop: 8, fontSize: 12 }}
          >
            {description}
          </Typography.Text>
        </div>

        {prefix && name.trim() && (
          <Typography.Text type="secondary">
            Emitted name: <code>{prefix}.{name.trim()}</code>
          </Typography.Text>
        )}
        {error && (
          <Typography.Text type="danger">
            Failed to load claims. Close and reopen to retry.
          </Typography.Text>
        )}
        <Table<CustomClaim>
          columns={columns}
          dataSource={claims ?? []}
          rowKey="name"
          loading={isLoading}
          pagination={false}
          size="small"
          locale={{ emptyText: "No custom claims" }}
        />
      </Space>
    </Drawer>
  );
}
