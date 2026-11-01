import { Button, Inline, Popover, Stack, Text, type Color } from "@yarcl/react";
import { useState, type ReactElement, type ReactNode } from "react";

interface ConfirmProps {
  title: ReactNode;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  color?: Color;
  onConfirm: () => unknown;
  children: ReactElement;
  [passthrough: string]: unknown;
}

export default function Confirm({
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  color = "danger",
  onConfirm,
  children,
  ...passthrough
}: ConfirmProps) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const confirm = async () => {
    setBusy(true);
    try {
      await onConfirm();
      setOpen(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Popover open={open} onOpenChange={setOpen} placement="bottom-end">
      <Popover.Trigger {...passthrough}>{children}</Popover.Trigger>
      <Popover.Content padding="md" role="alertdialog" aria-label={typeof title === "string" ? title : "Confirm"}>
        <Stack gap="sm" className="confirm-content">
          <Text textStyle="label">{title}</Text>
          {description && (
            <Text textStyle="caption" muted>
              {description}
            </Text>
          )}
          <Inline gap="sm" justify="end">
            <Button size="sm" variant="ghost" color="neutral" onClick={() => setOpen(false)}>
              {cancelLabel}
            </Button>
            <Button size="sm" color={color} loading={busy} onClick={confirm}>
              {confirmLabel}
            </Button>
          </Inline>
        </Stack>
      </Popover.Content>
    </Popover>
  );
}
