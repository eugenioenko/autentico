import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";
import { Button, Drawer, Inline, Input, Stack, Text, toast } from "@yarcl/react";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import type { UserClaim as CustomClaim } from "../types/userClaim";
import { DataTable, dataColumns } from "./DataTable";
import ConfirmIconButton from "./ConfirmIconButton";
import "./ClaimsDrawer.css";

interface ClaimsDrawerProps {
  open: boolean;
  title: string;
  description: ReactNode;
  claims: CustomClaim[];
  isLoading: boolean;
  isSaving: boolean;
  error?: boolean;
  prefix?: string;
  onSave: (name: string, value: string) => Promise<void>;
  onRemove: (name: string) => Promise<void>;
  onClose: () => void;
}

/**
 * Edits an owner's direct claim assignments, preserving drafts on failed saves.
 * An optional group prefix changes the emitted-name preview; saves use local names.
 */
export default function ClaimsDrawer({
  open,
  title,
  description,
  claims,
  isLoading,
  isSaving,
  error,
  prefix,
  onSave,
  onRemove,
  onClose,
}: ClaimsDrawerProps) {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");

  const reset = () => {
    setName("");
    setValue("");
  };

  const handleAdd = async () => {
    if (!name.trim()) return;
    try {
      await onSave(name.trim(), value);
      toast({ title: "Claim saved", color: "success" });
      reset();
    } catch (err) {
      const detail =
        (err as { response?: { data?: { error_description?: string } } })?.response?.data?.error_description ??
        "Failed to save claim";
      toast({ title: detail, color: "danger" });
    }
  };

  const onEnter = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !isSaving) handleAdd();
  };

  const columns = useMemo(() => {
    const handleDelete = async (claimName: string) => {
      try {
        await onRemove(claimName);
        toast({ title: "Claim removed", color: "success" });
      } catch {
        toast({ title: "Failed to remove claim", color: "danger" });
      }
    };
    const col = dataColumns<CustomClaim>();
    return col.columns([
      col.accessor("name", {
        header: prefix ? "Emitted name" : "Name",
        cell: (info) => (
          <Text truncate>{prefix ? `${prefix}.${info.getValue()}` : info.getValue()}</Text>
        ),
      }),
      col.accessor("value", {
        header: "Value",
        cell: (info) => <Text truncate>{info.getValue()}</Text>,
      }),
      col.display({
        id: "actions",
        header: "",
        cell: ({ row }) => (
          <ConfirmIconButton
            tooltip="Remove claim"
            aria-label={`Remove claim ${row.original.name}`}
            icon={<IconTrash />}
            color="danger"
            title="Remove this claim?"
            confirmLabel="Remove"
            onConfirm={() => handleDelete(row.original.name)}
          />
        ),
      }),
    ]);
  }, [prefix, onRemove]);

  return (
    <Drawer
      title={title}
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          onClose();
          reset();
        }
      }}
      side="right"
      size="md"
    >
      <Stack gap="md">
        <Stack gap="xs">
          <Text muted>Add claim</Text>
          <Inline gap="xs" wrap={false} className="claims-drawer-add">
            <Input
              className="claims-drawer-name"
              aria-label="Claim name"
              placeholder="name"
              maxLength={prefix ? 128 : 229}
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={onEnter}
            />
            <Input
              className="claims-drawer-value"
              aria-label="Claim value"
              placeholder="value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={onEnter}
            />
            <Button startIcon={<IconPlus />} onClick={handleAdd} loading={isSaving} disabled={!name.trim()}>
              Add
            </Button>
          </Inline>
          <Text textStyle="caption" muted>
            {description}
          </Text>
        </Stack>

        {prefix && name.trim() && (
          <Text muted>
            Emitted name:{" "}
            <Text as="code" textStyle="code">
              {prefix}.{name.trim()}
            </Text>
          </Text>
        )}
        {error && <Text color="danger">Failed to load claims. Close and reopen to retry.</Text>}
        <DataTable
          caption="Custom claims"
          data={claims ?? []}
          columns={columns}
          getRowId={(c) => c.name}
          loading={isLoading}
          pageSize={false}
          emptyTitle="No custom claims"
        />
      </Stack>
    </Drawer>
  );
}
