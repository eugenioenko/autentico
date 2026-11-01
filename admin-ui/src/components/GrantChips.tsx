import { Badge, Inline, Tooltip, type Color } from "@yarcl/react";

const GRANT_LABELS: Record<string, { abbr: string; color: Color }> = {
  authorization_code: { abbr: "AC", color: "info" },
  refresh_token: { abbr: "RT", color: "cyan" },
  client_credentials: { abbr: "CC", color: "purple" },
  password: { abbr: "P", color: "warning" },
};

interface GrantChipsProps {
  grants: string[];
}

export default function GrantChips({ grants }: GrantChipsProps) {
  if (grants.length === 0) return <Badge variant="soft" color="neutral">—</Badge>;
  return (
    <Inline gap="xs">
      {grants.map((t) => {
        const label = GRANT_LABELS[t] ?? { abbr: t.substring(0, 2).toUpperCase(), color: "neutral" };
        return (
          <Tooltip key={t} content={t.replace(/_/g, " ")}>
            <Badge variant="soft" color={label.color} tabIndex={0}>
              {label.abbr}
            </Badge>
          </Tooltip>
        );
      })}
    </Inline>
  );
}
