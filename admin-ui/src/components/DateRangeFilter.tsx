import { IconX } from "@tabler/icons-react";
import { DatePicker, IconButton, Inline, type DateRange } from "@yarcl/react";
import dayjs from "dayjs";
import { useState } from "react";

export function dateRangeParams(range: DateRange | null, field: string): Record<string, string | undefined> {
  return {
    [`${field}_from`]: range ? dayjs(range.from).startOf("day").toISOString() : undefined,
    [`${field}_to`]: range?.to ? dayjs(range.to).endOf("day").toISOString() : undefined,
  };
}

interface DateRangeFilterProps {
  label: string;
  value: DateRange | null;
  onChange: (range: DateRange | null) => void;
}

export default function DateRangeFilter({ label, value, onChange }: DateRangeFilterProps) {
  const [partial, setPartial] = useState<DateRange | null>(null);
  const shown = partial ?? value;

  const change = (next: DateRange | null) => {
    if (next && !next.to) {
      setPartial(next);
      return;
    }
    setPartial(null);
    onChange(next);
  };

  return (
    <Inline gap="xs" wrap={false}>
      <DatePicker mode="range" aria-label={label} placeholder={label} value={shown} onValueChange={change} />
      {shown && (
        <IconButton variant="ghost" color="neutral" aria-label="Clear dates" onClick={() => change(null)}>
          <IconX />
        </IconButton>
      )}
    </Inline>
  );
}
