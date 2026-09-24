import { QueryClient } from "@tanstack/react-query";

// Defaults: data stays fresh for 60s and is NOT auto-refetched on window focus /
// reconnect, so page remounts and tab switches don't burst ~10 requests at once.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
    },
  },
});
