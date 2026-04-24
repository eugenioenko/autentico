import { Tag, Tooltip } from "antd";

interface CountTooltipProps {
  items: string[];
  color?: string;
}

export default function CountTooltip({ items, color = "blue" }: CountTooltipProps) {
  if (items.length === 0) return <Tag>0</Tag>;
  return (
    <Tooltip title={items.join(", ")}>
      <Tag color={color}>{items.length}</Tag>
    </Tooltip>
  );
}
