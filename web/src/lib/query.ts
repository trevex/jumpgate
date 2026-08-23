/**
 * query.ts — react-query invalidation helpers.
 *
 * `useInvalidateList` returns a callback that refreshes a paginated list query
 * after a mutation. It cancels any in-flight fetch for that query *before*
 * invalidating: a request that was already running when the mutation completed
 * carries a pre-mutation snapshot, and react-query's request dedup would
 * otherwise settle the invalidation with that stale response — dropping the row
 * the mutation just created (or resurrecting one it deleted). Cancelling first
 * forces the invalidation to start a fresh fetch that reflects the write.
 */

import { useCallback } from "react";
import type { DescMethodUnary } from "@bufbuild/protobuf";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";

export function useInvalidateList() {
  const queryClient = useQueryClient();
  return useCallback(
    (schemas: DescMethodUnary | DescMethodUnary[]) => {
      const list = Array.isArray(schemas) ? schemas : [schemas];
      return Promise.all(
        list.map((schema) => {
          const key = createConnectQueryKey({ schema, cardinality: undefined });
          return queryClient
            .cancelQueries({ queryKey: key })
            .then(() => queryClient.invalidateQueries({ queryKey: key }));
        }),
      );
    },
    [queryClient],
  );
}
