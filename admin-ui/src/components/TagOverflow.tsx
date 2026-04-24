import { Tag, Tooltip } from "antd";

const MAX_VISIBLE = 2;

export default function TagOverflow({ items }: { items?: string[] }) {
  if (!items || items.length === 0) return null;

  const visible = items.slice(0, MAX_VISIBLE);
  const overflow = items.slice(MAX_VISIBLE);

  return (
    <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 2 }}>
      {visible.map((name) => (
        <Tag key={name}>{name}</Tag>
      ))}
      {overflow.length > 0 && (
        <Tooltip title={overflow.join(", ")}>
          <Tag>+{overflow.length}</Tag>
        </Tooltip>
      )}
    </span>
  );
}
