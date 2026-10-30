import ClaimsDrawer from "../ClaimsDrawer";
import {
  useUserClaims,
  useUpsertUserClaim,
  useDeleteUserClaim,
} from "../../hooks/useUserClaims";

interface UserClaimsDrawerProps {
  open: boolean;
  userId: string | null;
  username: string;
  onClose: () => void;
}

export default function UserClaimsDrawer({
  open,
  userId,
  username,
  onClose,
}: UserClaimsDrawerProps) {
  const { data, isLoading, isError } = useUserClaims(userId, open);
  const upsert = useUpsertUserClaim();
  const remove = useDeleteUserClaim();
  return (
    <ClaimsDrawer
      key={userId}
      open={open}
      title={`Custom claims for ${username}`}
      description={
        <>
          Emitted into tokens and UserInfo with the <code>custom_claims</code> scope.
          Individual claims override inherited group claims with the same full name.
        </>
      }
      claims={data ?? []}
      isLoading={isLoading}
      isSaving={upsert.isPending}
      error={isError}
      onSave={async (name, value) => {
        if (userId) await upsert.mutateAsync({ userId, claim: { name, value } });
      }}
      onRemove={async (name) => {
        if (userId) await remove.mutateAsync({ userId, name });
      }}
      onClose={onClose}
    />
  );
}
