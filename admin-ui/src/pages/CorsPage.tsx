import { useEffect, useState } from "react";
import { Alert, Button, Card, IconButton, Inline, Input, Spinner, Stack, Text, toast } from "@yarcl/react";
import { IconDeviceFloppy, IconPlus, IconTrash } from "@tabler/icons-react";
import { useSettings, useUpdateSettings } from "../hooks/useSettings";
import PageHeader from "../components/PageHeader";
import "./CorsPage.css";

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
      toast({ title: "CORS settings saved", color: "success" });
    } catch {
      toast({ title: "Failed to save CORS settings", color: "danger" });
    }
  };

  if (isLoading) {
    return (
      <div className="page-loading">
        <Spinner size="lg" label="Loading" />
      </div>
    );
  }

  return (
    <Stack gap="md" className="cors-page">
      <PageHeader
        title="CORS (Cross-Origin Resource Sharing)"
        description={
          <>
            Configure which origins are allowed to make cross-origin requests to Autentico. Use{" "}
            <Text as="code" textStyle="code">
              *
            </Text>{" "}
            to allow all origins. Remove all entries to disable CORS entirely.
          </>
        }
      />

      <Card>
        <Stack gap="md">
          <Text textStyle="label">Allowed Origins</Text>

          {origins.map((origin, index) => (
            <Inline key={index} gap="sm" wrap={false}>
              <Input
                className="cors-origin-input"
                aria-label={`Allowed origin ${index + 1}`}
                value={origin}
                onChange={(e) => handleChange(index, e.target.value)}
                placeholder="https://app.example.com"
              />
              <IconButton variant="outline" color="danger" aria-label={`Remove origin ${origin || index + 1}`} onClick={() => handleRemove(index)}>
                <IconTrash />
              </IconButton>
            </Inline>
          ))}

          <Button variant="outline" color="neutral" startIcon={<IconPlus />} onClick={handleAdd}>
            Add Origin
          </Button>

          {hasWildcard && (
            <Alert color="warning" title="Wildcard origin enabled">
              Using * allows any website to make cross-origin requests to your Autentico instance. This is suitable for
              development but not recommended for production.
            </Alert>
          )}

          {origins.length === 0 && (
            <Alert color="info" title="CORS is disabled">
              No origins are configured. Cross-origin browser requests will be blocked unless a reverse proxy handles CORS.
            </Alert>
          )}

          <Inline justify="end">
            <Button startIcon={<IconDeviceFloppy />} loading={updateSettings.isPending} onClick={handleSave}>
              Save
            </Button>
          </Inline>
        </Stack>
      </Card>
    </Stack>
  );
}
