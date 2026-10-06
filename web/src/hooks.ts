import { useQuery } from "@tanstack/react-query";
import type { Api } from "./api";
export function useApi<T>(
  api: Api,
  key: string,
  path: string,
  interval = 5000,
) {
  return useQuery({
    queryKey: [key],
    queryFn: ({ signal }) =>
      api.request<T>(path, { signal }).then((r) => r.value),
    refetchInterval: interval,
  });
}
