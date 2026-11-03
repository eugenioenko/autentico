import { Badge, Tooltip, type Color } from "@yarcl/react";

interface CountTooltipProps {
  items: string[];
  color?: Color;
}

export default function CountTooltip({ items, color = "info" }: CountTooltipProps) {
  if (items.length === 0) return <Badge variant="soft" color="neutral">0</Badge>;
  return (
    <Tooltip content={items.join(", ")}>
      <Badge variant="soft" color={color} tabIndex={0}>
        {items.length}
      </Badge>
    </Tooltip>
  );
}
