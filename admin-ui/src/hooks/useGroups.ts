import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listGroups,
  createGroup,
  updateGroup,
  deleteGroup,
  listMembers,
  addMember,
  removeMember,
} from "../api/groups";
import type { ListParams } from "../api/users";
import type { GroupCreateRequest, GroupUpdateRequest } from "../types/group";

const GROUPS_KEY = ["groups"] as const;

export function useGroups(params?: ListParams) {
  return useQuery({
    queryKey: [...GROUPS_KEY, params],
    queryFn: () => listGroups(params),
  });
}

export function useCreateGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: GroupCreateRequest) => createGroup(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: GROUPS_KEY });
    },
  });
}

export function useUpdateGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: GroupUpdateRequest }) =>
      updateGroup(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: GROUPS_KEY });
    },
  });
}

export function useDeleteGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteGroup(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: GROUPS_KEY });
    },
  });
}

export function useGroupMembers(groupId: string | null) {
  return useQuery({
    queryKey: ["group-members", groupId],
    queryFn: () => listMembers(groupId!),
    enabled: !!groupId,
  });
}

export function useAddMember() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ groupId, userId }: { groupId: string; userId: string }) =>
      addMember(groupId, userId),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["group-members", variables.groupId],
      });
      queryClient.invalidateQueries({ queryKey: GROUPS_KEY });
    },
  });
}

export function useRemoveMember() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ groupId, userId }: { groupId: string; userId: string }) =>
      removeMember(groupId, userId),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["group-members", variables.groupId],
      });
      queryClient.invalidateQueries({ queryKey: GROUPS_KEY });
    },
  });
}
