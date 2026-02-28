import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "../api/client";

export function useSettings() {
  return useQuery<Record<string, string>>({
    queryKey: ["settings"],
    queryFn: async () => {
      const { data } = await apiClient.get("/admin/api/settings");
      return data.data; // The backend wraps it in model.ApiResponse
    },
  });
}

export function useUpdateSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (updates: Record<string, string>) => {
      await apiClient.put("/admin/api/settings", updates);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
}
