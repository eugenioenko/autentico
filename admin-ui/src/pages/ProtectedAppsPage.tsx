import { useState } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Alert, App, Button, Form, Input, Modal, Popconfirm, Space, Switch, Table, Tag, Typography } from "antd";
import { PlusOutlined } from "@ant-design/icons";
import apiClient from "../api/client";

type ProtectedApp = {
  id: string; name: string; origin: string; allowed_return_paths: string[];
  client_id: string; session_ttl: string; is_active: boolean;
};
type Values = { name: string; origin: string; paths: string; session_ttl: string; is_active: boolean };
const endpoint = "/admin/api/protected-apps";

export default function ProtectedAppsPage() {
  const { message } = App.useApp();
  const cache = useQueryClient();
  const [form] = Form.useForm<Values>();
  const [editing, setEditing] = useState<ProtectedApp | null>(null);
  const [open, setOpen] = useState(false);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["protected-apps"],
    queryFn: async () => (await apiClient.get<{ data: ProtectedApp[] }>(endpoint)).data.data,
  });
  const save = useMutation({
    mutationFn: async (values: Values) => {
      const body = { name: values.name, origin: values.origin, allowed_return_paths: values.paths.split("\n").map(p => p.trim()).filter(Boolean), session_ttl: values.session_ttl, is_active: values.is_active };
      return editing ? apiClient.put(`${endpoint}/${editing.id}`, body) : apiClient.post(endpoint, body);
    },
    onSuccess: () => { void cache.invalidateQueries({ queryKey: ["protected-apps"] }); setOpen(false); message.success("Protected application saved"); },
    onError: (err: { response?: { data?: { error_description?: string } } }) => message.error(err.response?.data?.error_description ?? "Unable to save application"),
  });
  const remove = useMutation({
    mutationFn: (id: string) => apiClient.delete(`${endpoint}/${id}`),
    onSuccess: () => { void cache.invalidateQueries({ queryKey: ["protected-apps"] }); message.success("Application deleted and sessions revoked"); },
    onError: () => message.error("Unable to delete application"),
  });
  const edit = (app: ProtectedApp | null) => {
    setEditing(app);
    form.resetFields();
    form.setFieldsValue(app ? { ...app, paths: app.allowed_return_paths.join("\n") } : { paths: "/", session_ttl: "8h", is_active: true });
    setOpen(true);
  };
  return <Space direction="vertical" style={{ width: "100%" }} size="middle">
    <Space style={{ justifyContent: "space-between", width: "100%" }}>
      <Typography.Title level={3} style={{ margin: 0 }}>Protected Applications</Typography.Title>
      <Button type="primary" icon={<PlusOutlined />} onClick={() => edit(null)}>Add Application</Button>
    </Space>
    <Alert type="info" showIcon title="Protect applications behind a reverse proxy" description="Active users can access enabled applications after completing the configured login policy. Applications must be on the same site as Autentico. Configure your proxy using the ForwardAuth integration guide." />
    {isError && <Alert type="error" title="Unable to load protected applications" />}
    <Table<ProtectedApp> rowKey="id" loading={isLoading} dataSource={data} scroll={{ x: 850 }} columns={[
      { title: "Name", dataIndex: "name" },
      { title: "Origin", dataIndex: "origin" },
      { title: "Application ID", dataIndex: "id", render: value => <Typography.Text copyable>{value}</Typography.Text> },
      { title: "Session lifetime", dataIndex: "session_ttl" },
      { title: "Status", dataIndex: "is_active", render: active => <Tag color={active ? "green" : "default"}>{active ? "Enabled" : "Disabled"}</Tag> },
      { title: "Actions", render: (_, app) => <Space><Button onClick={() => edit(app)}>Edit</Button><Popconfirm title="Delete application and revoke all its sessions?" onConfirm={() => remove.mutateAsync(app.id)}><Button danger>Delete</Button></Popconfirm></Space> },
    ]} />
    <Modal open={open} title={editing ? "Edit Protected Application" : "Add Protected Application"} onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={save.isPending} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={values => save.mutate(values)}>
        <Form.Item name="name" label="Name" rules={[{ required: true, whitespace: true, max: 100 }]}><Input /></Form.Item>
        <Form.Item name="origin" label="Application origin" extra="HTTPS origin, for example https://dashboard.example.com. To change an origin, register a new application." rules={[{ required: true }, { type: "url" }]}><Input disabled={!!editing} /></Form.Item>
        <Form.Item name="paths" label="Allowed path prefixes" extra="One per line. / allows all application paths. Prefixes match complete path segments; authentication routes are reserved." rules={[{ required: true, whitespace: true }]}><Input.TextArea rows={3} /></Form.Item>
        <Form.Item name="session_ttl" label="Session lifetime" extra="Duration from 1s to 24h, for example 8h. Central session expiry and revocation also apply." rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="is_active" label="Enabled" valuePropName="checked" extra="Disabling revokes existing application sessions. Re-enabling requires a new application login."><Switch /></Form.Item>
      </Form>
    </Modal>
  </Space>;
}
