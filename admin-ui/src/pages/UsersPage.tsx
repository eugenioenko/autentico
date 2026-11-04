import { useState, useEffect, useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Alert, Badge, Button, IconButton, Inline, Stack, Tabs, Text, Tooltip, toast, type DateRange } from "@yarcl/react";
import { IconBan, IconDeviceLaptop, IconEdit, IconId, IconLockOpen, IconPlus, IconUsersGroup } from "@tabler/icons-react";
import { useUsers, useDeleteUser, useUnlockUser } from "../hooks/useUsers";
import { useGroups } from "../hooks/useGroups";
import { useDeletionRequests } from "../hooks/useDeletionRequests";
import type { ListParams } from "../api/users";
import type { UserResponseExt } from "../types/user";
import UserCreateForm from "../components/users/UserCreateForm";
import UserEditForm from "../components/users/UserEditForm";
import UserGroupsDrawer from "../components/users/UserGroupsDrawer";
import UserClaimsDrawer from "../components/users/UserClaimsDrawer";
import UserSessionsDrawer from "../components/users/UserSessionsDrawer";
import DeletionRequestsTab from "../components/users/DeletionRequestsTab";
import { DEFAULT_PAGE_SIZE } from "../constants/table";
import CountTooltip from "../components/CountTooltip";
import CopyText from "../components/CopyText";
import ConfirmIconButton from "../components/ConfirmIconButton";
import DateRangeFilter, { dateRangeParams } from "../components/DateRangeFilter";
import SearchInput from "../components/SearchInput";
import { DataTable, dataColumns, type DataFilter } from "../components/DataTable";

function isLocked(record: UserResponseExt): boolean {
  return !!record.locked_until && new Date(record.locked_until) > new Date();
}

function StatusBadge({ user }: { user: UserResponseExt }) {
  if (isLocked(user)) {
    return (
      <Badge variant="soft" color="warning">
        Locked
      </Badge>
    );
  }
  if (user.failed_login_attempts && user.failed_login_attempts > 0) {
    return (
      <Tooltip content={`${user.failed_login_attempts} failed attempt(s)`}>
        <Badge variant="soft" color="warning" tabIndex={0}>
          {user.failed_login_attempts} failed
        </Badge>
      </Tooltip>
    );
  }
  return (
    <Badge variant="soft" color="success">
      Active
    </Badge>
  );
}

export default function UsersPage() {
  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });
  const [dateRange, setDateRange] = useState<DateRange | null>(null);
  const [searchText, setSearchText] = useState("");

  const { data, isLoading, error } = useUsers(listParams);
  const { data: groups } = useGroups();
  const { data: deletionRequests } = useDeletionRequests();
  const { mutateAsync: deleteUser } = useDeleteUser();
  const { mutateAsync: unlockUser } = useUnlockUser();
  const location = useLocation();
  const navigate = useNavigate();

  const searchParams = new URLSearchParams(location.search);
  const activeTab = searchParams.get("tab") ?? "users";

  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<UserResponseExt | null>(null);
  const [groupsUser, setGroupsUser] = useState<UserResponseExt | null>(null);
  const [claimsUser, setClaimsUser] = useState<UserResponseExt | null>(null);
  const [sessionsUser, setSessionsUser] = useState<UserResponseExt | null>(null);

  useEffect(() => {
    if ((location.state as { create?: boolean })?.create) {
      setCreateOpen(true);
      window.history.replaceState({}, "");
    }
  }, [location.state]);

  const filters = useMemo<DataFilter[]>(
    () => [
      {
        key: "role",
        label: "Role",
        allLabel: "All roles",
        options: [
          { value: "admin", label: "Admin" },
          { value: "user", label: "User" },
        ],
      },
      {
        key: "totp_verified",
        label: "MFA",
        allLabel: "Any MFA",
        options: [
          { value: "1", label: "Enrolled" },
          { value: "0", label: "No" },
        ],
      },
      {
        key: "is_email_verified",
        label: "Verified",
        allLabel: "Any verification",
        options: [
          { value: "1", label: "Yes" },
          { value: "0", label: "No" },
        ],
      },
      {
        key: "group",
        label: "Groups",
        allLabel: "All groups",
        options: (groups?.items ?? []).map((g) => ({ value: g.name, label: g.name })),
      },
    ],
    [groups],
  );

  const columns = useMemo(() => {
    const handleDelete = async (id: string) => {
      try {
        await deleteUser(id);
        toast({ title: "User deactivated", color: "success" });
      } catch {
        toast({ title: "Failed to deactivate user", color: "danger" });
      }
    };

    const handleUnlock = async (id: string) => {
      try {
        await unlockUser(id);
        toast({ title: "User unlocked", color: "success" });
      } catch {
        toast({ title: "Failed to unlock user", color: "danger" });
      }
    };

    const col = dataColumns<UserResponseExt>();
    return col.columns([
      col.accessor("username", {
        header: "Username",
        cell: (info) => <Text truncate>{info.getValue()}</Text>,
      }),
      col.accessor("email", {
        header: "Email",
        cell: (info) => <CopyText text={info.getValue() ?? ""} />,
      }),
      col.accessor("role", {
        header: "Role",
        cell: (info) => (
          <Badge variant="soft" color={info.getValue() === "admin" ? "danger" : "info"}>
            {info.getValue()}
          </Badge>
        ),
      }),
      col.accessor("totp_verified", {
        id: "mfa",
        header: "MFA",
        enableSorting: false,
        cell: (info) => (
          <Badge variant="soft" color={info.getValue() ? "success" : "neutral"}>
            {info.getValue() ? "Enrolled" : "No"}
          </Badge>
        ),
      }),
      col.accessor("is_email_verified", {
        id: "verified",
        header: "Verified",
        enableSorting: false,
        cell: (info) => (
          <Badge variant="soft" color={info.getValue() ? "success" : "warning"}>
            {info.getValue() ? "Yes" : "No"}
          </Badge>
        ),
      }),
      col.display({
        id: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge user={row.original} />,
      }),
      col.display({
        id: "groups",
        header: "Groups",
        meta: { width: 80 },
        cell: ({ row }) => <CountTooltip items={row.original.groups ?? []} />,
      }),
      col.accessor("created_at", {
        header: "Created",
        cell: (info) => (info.getValue() ? new Date(info.getValue()).toLocaleDateString() : "-"),
      }),
      col.display({
        id: "actions",
        header: "Actions",
        cell: ({ row }) => {
          const record = row.original;
          return (
            <Inline gap="xs" wrap={false}>
              <ConfirmIconButton
                tooltip="Deactivate user"
                aria-label="Deactivate user"
                color="danger"
                icon={<IconBan />}
                title="Deactivate this user?"
                description="The user will no longer be able to log in."
                confirmLabel="Deactivate"
                onConfirm={() => handleDelete(record.id)}
              />
              <Tooltip content="Manage groups">
                <IconButton variant="ghost" color="neutral" size="sm" aria-label="Manage user groups" onClick={() => setGroupsUser(record)}>
                  <IconUsersGroup />
                </IconButton>
              </Tooltip>
              <Tooltip content="Custom claims">
                <IconButton
                  variant="ghost"
                  color="neutral"
                  size="sm"
                  aria-label={`Custom claims for ${record.username}`}
                  onClick={() => setClaimsUser(record)}
                >
                  <IconId />
                </IconButton>
              </Tooltip>
              <Tooltip content="View sessions">
                <IconButton variant="ghost" color="neutral" size="sm" aria-label="View user sessions" onClick={() => setSessionsUser(record)}>
                  <IconDeviceLaptop />
                </IconButton>
              </Tooltip>
              <Tooltip content="Edit user">
                <IconButton variant="ghost" color="neutral" size="sm" aria-label="Edit user" onClick={() => setEditUser(record)}>
                  <IconEdit />
                </IconButton>
              </Tooltip>
              {isLocked(record) && (
                <ConfirmIconButton
                  tooltip="Unlock user"
                  aria-label="Unlock user"
                  icon={<IconLockOpen />}
                  title="Unlock this user?"
                  description="This will reset failed login attempts and remove the lockout."
                  confirmLabel="Unlock"
                  confirmColor="primary"
                  onConfirm={() => handleUnlock(record.id)}
                />
              )}
            </Inline>
          );
        },
      }),
    ]);
  }, [deleteUser, unlockUser]);

  if (error) {
    return <Alert color="danger" title="Failed to load users" />;
  }

  const deletionCount = deletionRequests?.total ?? 0;

  const handleTabChange = (key: string) => {
    navigate(key === "users" ? "/users" : `/users?tab=${key}`, { replace: true });
  };

  const handleDateRange = (range: DateRange | null) => {
    setDateRange(range);
    setListParams((prev) => ({ ...prev, offset: 0, ...dateRangeParams(range, "created_at") }));
  };

  return (
    <Stack gap="md">
      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <Tabs.List aria-label="Users">
          <Tabs.Trigger value="users">Users</Tabs.Trigger>
          <Tabs.Trigger value="deletions">
            <Inline as="span" gap="xs" wrap={false}>
              Deletion Requests
              {deletionCount > 0 && (
                <Badge variant="solid" color="danger" size="sm">
                  {deletionCount}
                </Badge>
              )}
            </Inline>
          </Tabs.Trigger>
        </Tabs.List>
        <Tabs.Panel value="users">
          {activeTab === "users" && (
            <Stack gap="md">
              <DataTable
                caption="Users"
                data={data?.items ?? []}
                columns={columns}
                getRowId={(u) => u.id}
                loading={isLoading}
                filters={filters}
                actions={
                  <Button startIcon={<IconPlus />} onClick={() => setCreateOpen(true)}>
                    Create User
                  </Button>
                }
                toolbar={
                  <>
                    <SearchInput
                      placeholder="Search users..."
                      value={searchText}
                      onValueChange={setSearchText}
                      onSearch={(value) => setListParams((prev) => ({ ...prev, search: value || undefined, offset: 0 }))}
                    />
                    <DateRangeFilter label="Created between" value={dateRange} onChange={handleDateRange} />
                  </>
                }
                emptyTitle="No users found"
                server={{
                  params: listParams,
                  onParamsChange: setListParams,
                  total: data?.total ?? 0,
                  totalLabel: (total) => `${total} users`,
                }}
              />
            </Stack>
          )}
        </Tabs.Panel>
        <Tabs.Panel value="deletions">{activeTab === "deletions" && <DeletionRequestsTab />}</Tabs.Panel>
      </Tabs>

      <UserCreateForm open={createOpen} onClose={() => setCreateOpen(false)} />

      <UserEditForm open={!!editUser} user={editUser} onClose={() => setEditUser(null)} />

      <UserGroupsDrawer
        open={!!groupsUser}
        userId={groupsUser?.id ?? null}
        username={groupsUser?.username ?? ""}
        onClose={() => setGroupsUser(null)}
      />
      <UserClaimsDrawer
        open={!!claimsUser}
        userId={claimsUser?.id ?? null}
        username={claimsUser?.username ?? ""}
        onClose={() => setClaimsUser(null)}
      />

      <UserSessionsDrawer
        open={!!sessionsUser}
        userId={sessionsUser?.id ?? null}
        username={sessionsUser?.username ?? ""}
        onClose={() => setSessionsUser(null)}
      />
    </Stack>
  );
}
