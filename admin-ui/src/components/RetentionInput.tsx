import { Select, Space } from "antd";
import DurationInput from "./DurationInput";

type Mode = "disabled" | "forever" | "custom";

function parseMode(raw: string | undefined): { mode: Mode; duration: string } {
  if (!raw || raw === "0") return { mode: "disabled", duration: "" };
  if (raw === "-1") return { mode: "forever", duration: "" };
  return { mode: "custom", duration: raw };
}

interface Props {
  value?: string;
  onChange?: (v: string) => void;
}

export default function RetentionInput({ value, onChange }: Props) {
  const { mode, duration } = parseMode(value);

  const handleModeChange = (m: Mode) => {
    if (m === "disabled") onChange?.("0");
    else if (m === "forever") onChange?.("-1");
    else onChange?.(duration || "720h");
  };

  return (
    <Space direction="vertical" size="small">
      <Select
        value={mode}
        onChange={handleModeChange}
        style={{ width: 240 }}
        options={[
          { value: "disabled", label: "已禁用" },
          { value: "forever", label: "永久保留" },
          { value: "custom", label: "自定义保留期" },
        ]}
      />
      {mode === "custom" && (
        <DurationInput value={duration} onChange={(v) => onChange?.(v)} />
      )}
    </Space>
  );
}
