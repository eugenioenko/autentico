import { IconButton, Tooltip, type Color } from "@yarcl/react";
import type { ReactNode } from "react";
import Confirm from "./Confirm";

interface ConfirmIconButtonProps {
  tooltip: string;
  "aria-label": string;
  icon: ReactNode;
  color?: Color;
  title: ReactNode;
  description?: ReactNode;
  confirmLabel: string;
  confirmColor?: Color;
  onConfirm: () => unknown;
}

export default function ConfirmIconButton({
  tooltip,
  "aria-label": ariaLabel,
  icon,
  color = "neutral",
  title,
  description,
  confirmLabel,
  confirmColor = "danger",
  onConfirm,
}: ConfirmIconButtonProps) {
  return (
    <Tooltip content={tooltip}>
      <Confirm title={title} description={description} confirmLabel={confirmLabel} color={confirmColor} onConfirm={onConfirm}>
        <IconButton variant="ghost" color={color} size="sm" aria-label={ariaLabel}>
          {icon}
        </IconButton>
      </Confirm>
    </Tooltip>
  );
}
