import { useEffect, useState } from "react";
import { Typography, Input, Button, Alert, Space, message, Spin, Card } from "antd";
import { SaveOutlined, PlusOutlined, DeleteOutlined } from "@ant-design/icons";
import { useSettings, useUpdateSettings } from "../hooks/useSettings";

const { Title, Paragraph, Text } = Typography;

export default function CorsPage() {
  const { data: settings, isLoading } = useSettings();
  const updateSettings = useUpdateSettings();
  const [origins, setOrigins] = useState<string[]>([]);

  useEffect(() => {
    if (settings?.cors_allowed_origins !== undefined) {
      const raw = settings.cors_allowed_origins;
      if (raw === "") {
        setOrigins([]);
      } else {
        setOrigins(raw.split(",").map((o) => o.trim()).filter(Boolean));
      }
    }
  }, [settings]);

  const hasWildcard = origins.some((o) => o === "*");

  const handleAdd = () => {
    setOrigins([...origins, ""]);
  };

  const handleChange = (index: number, value: string) => {
    const updated = [...origins];
    updated[index] = value;
    setOrigins(updated);
  };

  const handleRemove = (index: number) => {
    setOrigins(origins.filter((_, i) => i !== index));
  };

  const handleSave = async () => {
    const cleaned = origins.map((o) => o.trim()).filter(Boolean);
    try {
      await updateSettings.mutateAsync({
        cors_allowed_origins: cleaned.join(","),
      });
      message.success("CORS settings saved");
    } catch {
      message.error("Failed to save CORS settings");
    }
  };

  if (isLoading) {
    return <Spin />;
  }

  return (
    <div style={{ maxWidth: 720 }}>
      <Title level={3}>CORS (Cross-Origin Resource Sharing)</Title>
      <Paragraph type="secondary">
        Configure which origins are allowed to make cross-origin requests to
        Autentico. Use <Text code>*</Text> to allow all origins. Remove all
        entries to disable CORS entirely.
      </Paragraph>

      <Card>
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <div>
            <Text strong>Allowed Origins</Text>
          </div>

          {origins.map((origin, index) => (
            <Space key={index} style={{ width: "100%" }}>
              <Input
                style={{ width: 480 }}
                value={origin}
                onChange={(e) => handleChange(index, e.target.value)}
                placeholder="https://app.example.com"
              />
              <Button
                icon={<DeleteOutlined />}
                danger
                onClick={() => handleRemove(index)}
              />
            </Space>
          ))}

          <Button
            type="dashed"
            icon={<PlusOutlined />}
            onClick={handleAdd}
            style={{ width: "100%" }}
          >
            Add Origin
          </Button>

          {hasWildcard && (
            <Alert
              type="warning"
              showIcon
              message="Wildcard origin enabled"
              description="Using * allows any website to make cross-origin requests to your Autentico instance. This is suitable for development but not recommended for production."
            />
          )}

          {origins.length === 0 && (
            <Alert
              type="info"
              showIcon
              message="CORS is disabled"
              description="No origins are configured. Cross-origin browser requests will be blocked unless a reverse proxy handles CORS."
            />
          )}

          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <Button
              type="primary"
              icon={<SaveOutlined />}
              loading={updateSettings.isPending}
              onClick={handleSave}
            >
              Save
            </Button>
          </div>
        </Space>
      </Card>
    </div>
  );
}
