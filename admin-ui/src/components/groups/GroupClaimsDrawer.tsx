import { Text } from "@yarcl/react";
import ClaimsDrawer from "../ClaimsDrawer";
import {
  useGroupClaims,
  useUpsertGroupClaim,
  useDeleteGroupClaim,
} from "../../hooks/useGroupClaims";
import { useSettings } from "../../hooks/useSettings";
import type { Group } from "../../types/group";

interface GroupClaimsDrawerProps {
  group: Group | null;
  onClose: () => void;
}

/** Connects the shared editor to one group's local claims and emitted-name prefix. */
export default function GroupClaimsDrawer({ group, onClose }: GroupClaimsDrawerProps) {
  const { data, isLoading, isError } = useGroupClaims(group?.id ?? null);
  const { data: settings } = useSettings();
  const merged = settings?.merge_group_claims === "true";
  const upsert = useUpsertGroupClaim();
  const remove = useDeleteGroupClaim();
  return (
    <ClaimsDrawer
      key={group?.id}
      open={!!group}
      title={`Custom claims for group ${group?.name ?? ""}`}
      prefix={merged ? "" : group?.name}
      description={
        <>
          Members inherit these claims with the{" "}
          <Text as="code" textStyle="code">
            custom_claims
          </Text>{" "}
          scope.{" "}
          {merged ? (
            <>
              Merge Group Claims is enabled: claims are emitted under their local names, and values from all of a
              member's groups are combined into an array. Individual claims with the same name override group values.
            </>
          ) : (
            <>
              Individual claims with the same full name override group values. Renaming this group changes its emitted
              claim names.
            </>
          )}
        </>
      }
      claims={data ?? []}
      isLoading={isLoading}
      isSaving={upsert.isPending}
      error={isError}
      onSave={async (name, value) => {
        if (group) {
          await upsert.mutateAsync({ groupId: group.id, claim: { name, value } });
        }
      }}
      onRemove={async (name) => {
        if (group) await remove.mutateAsync({ groupId: group.id, name });
      }}
      onClose={onClose}
    />
  );
}
