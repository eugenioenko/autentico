import { Form, Input, Switch, Space } from "antd";
import { ExclamationCircleOutlined } from "@ant-design/icons";
import { appTip } from "./clientTips";

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

function validateWebUri(_: unknown, value?: string) {
  if (!value) return Promise.resolve();
  try {
    const u = new URL(value);
    if (u.username || u.password) throw new Error();
    if (u.protocol === "https:") return Promise.resolve();
    if (u.protocol === "http:" && LOOPBACK_HOSTS.includes(u.hostname)) {
      return Promise.resolve();
    }
  } catch {
    return Promise.reject(new Error("Must be a valid URL"));
  }
  return Promise.reject(
    new Error("Must use https (http is only allowed for localhost)"),
  );
}

export default function AccountAppFields() {
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Form.Item
        label="Show in Account Dashboard"
        name="show_in_account"
        valuePropName="checked"
        tooltip={{ title: appTip("show_in_account"), icon: <ExclamationCircleOutlined /> }}
      >
        <Switch />
      </Form.Item>

      <Form.Item
        label="Application URL"
        name="client_uri"
        rules={[{ validator: validateWebUri }]}
        tooltip={{ title: appTip("client_uri"), icon: <ExclamationCircleOutlined /> }}
      >
        <Input placeholder="https://app.example.com" />
      </Form.Item>

      <Form.Item
        label="Logo URL"
        name="logo_uri"
        rules={[{ validator: validateWebUri }]}
        tooltip={{ title: appTip("logo_uri"), icon: <ExclamationCircleOutlined /> }}
      >
        <Input placeholder="https://app.example.com/logo.png" />
      </Form.Item>

      <Form.Item
        label="Description"
        name="description"
        rules={[
          { max: 1000, message: "At most 1000 characters" },
          { pattern: /^[^<>]*$/, message: "Must not contain < or >" },
        ]}
        tooltip={{ title: appTip("description"), icon: <ExclamationCircleOutlined /> }}
      >
        <Input.TextArea rows={2} />
      </Form.Item>
    </Space>
  );
}
