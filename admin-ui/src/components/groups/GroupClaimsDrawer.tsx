import ClaimsDrawer from "../ClaimsDrawer";
import {
  useGroupClaims,
  useUpsertGroupClaim,
  useDeleteGroupClaim,
} from "../../hooks/useGroupClaims";
import type { Group } from "../../types/group";

interface GroupClaimsDrawerProps {
  group: Group | null;
  onClose: () => void;
}

export default function GroupClaimsDrawer({ group, onClose }: GroupClaimsDrawerProps) {
  const { data, isLoading, isError } = useGroupClaims(group?.id ?? null);
  const upsert = useUpsertGroupClaim();
  const remove = useDeleteGroupClaim();
  return (
    <ClaimsDrawer
      key={group?.id}
      open={!!group}
      title={`Custom claims for group ${group?.name ?? ""}`}
      prefix={group?.name}
      description={
        <>
          Members inherit these claims with the <code>custom_claims</code> scope.
          Individual claims with the same full name override group values.
          Renaming this group changes its emitted claim names.
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
