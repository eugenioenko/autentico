import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listFederationProviders,
  createFederationProvider,
  updateFederationProvider,
  deleteFederationProvider,
} from "../api/federation";
import type {
  FederationProviderCreateRequest,
  FederationProviderUpdateRequest,
} from "../types/federation";
import type { ListParams } from "../api/users";

const FEDERATION_KEY = ["federation"] as const;

export function useFederationProviders(params?: ListParams) {
  return useQuery({
    queryKey: [...FEDERATION_KEY, params],
    queryFn: () => listFederationProviders(params),
  });
}

export function useCreateFederationProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: FederationProviderCreateRequest) =>
      createFederationProvider(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: FEDERATION_KEY });
    },
  });
}

export function useUpdateFederationProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: FederationProviderUpdateRequest }) =>
      updateFederationProvider(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: FEDERATION_KEY });
    },
  });
}

export function useDeleteFederationProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteFederationProvider(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: FEDERATION_KEY });
    },
  });
}
