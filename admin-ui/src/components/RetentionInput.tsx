import { useId } from "react";
import { Select, Stack } from "@yarcl/react";
import DurationInput from "./DurationInput";
import "./RetentionInput.css";

type Mode = "disabled" | "forever" | "custom";

const MODE_OPTIONS: { value: Mode; label: string }[] = [
  { value: "disabled", label: "Disabled" },
  { value: "forever", label: "Keep forever" },
  { value: "custom", label: "Custom retention" },
];

function parseMode(raw: string | undefined): { mode: Mode; duration: string } {
  if (!raw || raw === "0") return { mode: "disabled", duration: "" };
  if (raw === "-1") return { mode: "forever", duration: "" };
  return { mode: "custom", duration: raw };
}

interface Props {
  value?: string;
  onChange?: (v: string) => void;
  onBlur?: () => void;
}

export default function RetentionInput({ value, onChange, onBlur }: Props) {
  const durationId = useId();
  const { mode, duration } = parseMode(value);

  const handleModeChange = (m: Mode | null) => {
    if (m === "disabled") onChange?.("0");
    else if (m === "forever") onChange?.("-1");
    else if (m === "custom") onChange?.(duration || "720h");
  };

  return (
    <Stack gap="sm">
      <Select className="retention-input-mode" value={mode} onValueChange={handleModeChange} onBlur={onBlur} options={MODE_OPTIONS} />
      {mode === "custom" && (
        <DurationInput id={durationId} aria-label="Retention duration" value={duration} onChange={(v) => onChange?.(v)} />
      )}
    </Stack>
  );
}
