import { Typography, Tooltip } from "antd";
import { CopyOutlined, CheckOutlined } from "@ant-design/icons";
import { useState } from "react";

interface CopyTextProps {
  text: string;
  children?: React.ReactNode;
}

export default function CopyText({ text, children }: CopyTextProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        maxWidth: "100%",
        minWidth: 0,
        gap: 4,
      }}
    >
      <span
        style={{
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          minWidth: 0,
        }}
      >
        {children ?? (text || "—")}
      </span>
      {text && (
        <Tooltip title={copied ? "Copied" : "Copy"}>
          <Typography.Link
            onClick={handleCopy}
            style={{ flexShrink: 0, fontSize: "inherit", lineHeight: 1 }}
          >
            {copied ? <CheckOutlined /> : <CopyOutlined />}
          </Typography.Link>
        </Tooltip>
      )}
    </span>
  );
}
