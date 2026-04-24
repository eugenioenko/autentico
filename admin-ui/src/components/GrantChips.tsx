import { Tag, Tooltip, Space } from "antd";

const GRANT_LABELS: Record<string, { abbr: string; color: string }> = {
  authorization_code: { abbr: "AC", color: "blue" },
  refresh_token: { abbr: "RT", color: "cyan" },
  client_credentials: { abbr: "CC", color: "purple" },
  password: { abbr: "P", color: "orange" },
};

interface GrantChipsProps {
  grants: string[];
}

export default function GrantChips({ grants }: GrantChipsProps) {
  if (grants.length === 0) return <Tag>—</Tag>;
  return (
    <Space size={[2, 0]} wrap>
      {grants.map((t) => {
        const label = GRANT_LABELS[t] ?? {
          abbr: t.substring(0, 2).toUpperCase(),
          color: "default",
        };
        return (
          <Tooltip key={t} title={t.replace(/_/g, " ")}>
            <Tag color={label.color} style={{ margin: 0 }}>
              {label.abbr}
            </Tag>
          </Tooltip>
        );
      })}
    </Space>
  );
}
