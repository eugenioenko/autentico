import { useState } from "react";
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
import {
  useUserClaims,
  useUpsertUserClaim,
  useDeleteUserClaim,
} from "../../hooks/useUserClaims";
import type { UserClaim } from "../../types/userClaim";

interface UserClaimsDrawerProps {
  open: boolean;
  userId: string | null;
  username: string;
  onClose: () => void;
}

export default function UserClaimsDrawer({
  open,
  userId,
  username,
  onClose,
}: UserClaimsDrawerProps) {
  const { message } = App.useApp();
  const { data: claims, isLoading } = useUserClaims(userId, open);
  const upsertClaim = useUpsertUserClaim();
  const deleteClaim = useDeleteUserClaim();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");

  const reset = () => {
    setName("");
    setValue("");
  };

  const handleAdd = async () => {
    if (!userId || !name.trim()) return;
    try {
      await upsertClaim.mutateAsync({
        userId,
        claim: { name: name.trim(), value },
      });
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
    if (!userId) return;
    try {
      await deleteClaim.mutateAsync({ userId, name: claimName });
      message.success("Claim removed");
    } catch {
      message.error("Failed to remove claim");
    }
  };

  const columns: ColumnsType<UserClaim> = [
    { title: "Name", dataIndex: "name", key: "name", ellipsis: true },
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
      title={`Custom claims for ${username}`}
      open={open}
      onClose={() => {
        onClose();
        reset();
      }}
      width={480}
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
              placeholder="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onPressEnter={handleAdd}
            />
            <Input
              style={{ width: "60%" }}
              placeholder="value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onPressEnter={handleAdd}
            />
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleAdd}
              loading={upsertClaim.isPending}
              disabled={!name.trim()}
            >
              Add
            </Button>
          </Space.Compact>
          <Typography.Text
            type="secondary"
            style={{ display: "block", marginTop: 8, fontSize: 12 }}
          >
            Emitted into tokens and UserInfo when the client is granted the{" "}
            <code>custom_claims</code> scope.
          </Typography.Text>
        </div>

        <Table<UserClaim>
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
