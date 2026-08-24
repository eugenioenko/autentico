import { useEffect, useState } from "react";
import { Typography, Input, Button, Alert, Space, Spin, Card, App } from "antd";
import { SaveOutlined, PlusOutlined, DeleteOutlined } from "@ant-design/icons";
import { useSettings, useUpdateSettings } from "../hooks/useSettings";
import { useTranslation, Trans } from "react-i18next";

const { Title, Paragraph, Text } = Typography;

export default function CorsPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
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
      message.success(t("cors.corsSaved"));
    } catch {
      message.error(t("cors.corsSaveFailed"));
    }
  };

  if (isLoading) {
    return <Spin />;
  }

  return (
    <div style={{ maxWidth: 720, flex: 1, overflow: "auto" }}>
      <Title level={3}>{t("cors.title")}</Title>
      <Paragraph type="secondary">
        <Trans i18nKey="cors.description">
          Configure which origins are allowed to make cross-origin requests to Autentico. Use <Text code>*</Text> to allow all origins. Remove all entries to fully disable CORS.
        </Trans>
      </Paragraph>

      <Card>
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <div>
            <Text strong>{t("cors.allowedOrigins")}</Text>
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
            {t("cors.addOrigin")}
          </Button>

          {hasWildcard && (
            <Alert
              type="warning"
              showIcon
              message={t("cors.wildcardEnabled")}
              description={t("cors.wildcardDesc")}
            />
          )}

          {origins.length === 0 && (
            <Alert
              type="info"
              showIcon
              message={t("cors.corsDisabled")}
              description={t("cors.corsDisabledDesc")}
            />
          )}

          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <Button
              type="primary"
              icon={<SaveOutlined />}
              loading={updateSettings.isPending}
              onClick={handleSave}
            >
              {t("common.save")}
            </Button>
          </div>
        </Space>
      </Card>
    </div>
  );
}
