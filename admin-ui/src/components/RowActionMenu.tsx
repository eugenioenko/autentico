import { Button, Dialog, IconButton, Menu, Tooltip, type Color } from "@yarcl/react";
import { IconDotsVertical } from "@tabler/icons-react";
import { Fragment, useState } from "react";

export interface RowAction {
  label: string;
  onSelect: () => unknown;
  danger?: boolean;
  confirmation?: {
    title: string;
    description?: string;
    confirmLabel: string;
    color?: Color;
  };
}

export default function RowActionMenu({ label, actions }: { label: string; actions: RowAction[] }) {
  const [pending, setPending] = useState<RowAction | null>(null);
  const [busy, setBusy] = useState(false);

  const confirm = async () => {
    if (!pending || busy) return;
    setBusy(true);
    try {
      await pending.onSelect();
      setPending(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Menu placement="bottom-end">
        <Tooltip content="More actions">
          <Menu.Trigger>
            <IconButton variant="ghost" color="neutral" size="sm" aria-label={label}>
              <IconDotsVertical />
            </IconButton>
          </Menu.Trigger>
        </Tooltip>
        <Menu.Content aria-label={label}>
          {actions.map((action, index) => (
            <Fragment key={action.label}>
              {action.danger && index > 0 && !actions[index - 1].danger && <Menu.Separator />}
              <Menu.Item
                color={action.danger ? "danger" : undefined}
                onSelect={() => {
                  if (action.confirmation) setPending(action);
                  else action.onSelect();
                }}
              >
                {action.label}
              </Menu.Item>
            </Fragment>
          ))}
        </Menu.Content>
      </Menu>
      <Dialog
        title={pending?.confirmation?.title ?? ""}
        description={pending?.confirmation?.description}
        open={!!pending}
        onOpenChange={(open) => !open && !busy && setPending(null)}
        size="sm"
        footer={
          <>
            <Button variant="ghost" color="neutral" disabled={busy} onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button color={pending?.confirmation?.color ?? "danger"} loading={busy} onClick={confirm}>
              {pending?.confirmation?.confirmLabel}
            </Button>
          </>
        }
      />
    </>
  );
}
