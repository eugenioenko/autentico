import { IconCheck, IconCopy } from "@tabler/icons-react";
import { IconButton, Inline, Text, Tooltip, toast } from "@yarcl/react";
import { useState, type ReactNode } from "react";

interface CopyTextProps {
  text: string;
  children?: ReactNode;
  code?: boolean;
}

export default function CopyText({ text, children, code }: CopyTextProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast({ title: "Could not copy", description: text, color: "danger" });
    }
  };

  const action = copied ? "Copied" : "Copy";
  return (
    <Inline gap="xs" wrap={false} className="copy-text">
      <Text as="span" truncate textStyle={code ? "code" : undefined}>
        {children ?? (text || "—")}
      </Text>
      {text && (
        <Tooltip content={action}>
          <IconButton size="sm" variant="ghost" color={copied ? "success" : "neutral"} aria-label={action} onClick={handleCopy}>
            {copied ? <IconCheck /> : <IconCopy />}
          </IconButton>
        </Tooltip>
      )}
    </Inline>
  );
}
