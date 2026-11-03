import { useId } from "react";
import { Inline, NumberInput, Select } from "@yarcl/react";
import "./DurationInput.css";

const units = [
  { value: "s", label: "Seconds" },
  { value: "m", label: "Minutes" },
  { value: "h", label: "Hours" },
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
  onBlur?: () => void;
  id?: string;
  "aria-label"?: string;
}

export default function DurationInput({ value, onChange, onBlur, id, "aria-label": ariaLabel }: Props) {
  const unitId = useId();
  const { num, unit } = parse(value);

  const fire = (nextNum: number | null, nextUnit: string) => {
    onChange?.(format(nextNum, nextUnit));
  };

  return (
    <Inline gap="xs" wrap={false} className="duration-input">
      <NumberInput
        id={id}
        aria-label={ariaLabel}
        className="duration-input-number"
        min={0}
        value={num}
        onValueChange={(v) => fire(v, unit)}
        onBlur={onBlur}
      />
      <Select
        id={unitId}
        aria-label="Unit"
        className="duration-input-unit"
        value={unit}
        onValueChange={(u) => fire(num, u ?? unit)}
        options={units}
      />
    </Inline>
  );
}
