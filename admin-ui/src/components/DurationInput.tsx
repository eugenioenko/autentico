import { InputNumber, Select, Space } from "antd";

const units = [
  { value: "s", label: "秒" },
  { value: "m", label: "分钟" },
  { value: "h", label: "小时" },
];

function parse(raw: string | undefined): { num: number | null; unit: string } {
  if (!raw) return { num: null, unit: "h" };
  const match = raw.match(/^(\d+(?:\.\d+)?)\s*(s|m|h)$/);
  if (!match) return { num: null, unit: "h" };
  return { num: parseFloat(match[1]), unit: match[2] };
}

function format(num: number | null, unit: string): string {
  if (num == null || isNaN(num)) return "";
  return `${num}${unit}`;
}

interface Props {
  value?: string;
  onChange?: (v: string) => void;
}

export default function DurationInput({ value, onChange }: Props) {
  const { num, unit } = parse(value);

  const fire = (nextNum: number | null, nextUnit: string) => {
    onChange?.(format(nextNum, nextUnit));
  };

  return (
    <Space.Compact style={{ display: "flex", maxWidth: 400 }}>
      <InputNumber
        min={0}
        value={num}
        onChange={(v) => fire(v, unit)}
        style={{ flex: 1 }}
      />
      <Select
        value={unit}
        onChange={(u) => fire(num, u)}
        options={units}
        style={{ width: 130 }}
      />
    </Space.Compact>
  );
}
