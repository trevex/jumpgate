import { useInfiniteQuery } from "@connectrpc/connect-query";
import { Send } from "lucide-react";
import { listPoliciesForAsset } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { connectErrorMessage } from "@/lib/format";
import { PolicyRuleCard } from "./policy-rule-card";

const PAGE_SIZE = 50;

/** "Requestable via": one rule card per policy, each with an on-demand roster. */
export function RequestableVia({ assetId }: { assetId: string }) {
  const {
    data, isLoading, isError, error, refetch,
    fetchNextPage, hasNextPage, isFetchingNextPage,
  } = useInfiniteQuery(
    listPoliciesForAsset,
    { assetId, pageSize: PAGE_SIZE, pageToken: "" },
    { pageParamKey: "pageToken", getNextPageParam: (last) => last.nextPageToken || undefined },
  );

  const policies = data?.pages.flatMap((p) => p.policies) ?? [];

  if (isLoading) return <LoadingRows count={2} label="Loading policies" />;
  if (isError) return <ErrorState size="sm" message={connectErrorMessage(error)} onRetry={() => void refetch()} />;
  if (policies.length === 0) return <EmptyState icon={Send} size="sm" message="Not requestable yet." />;

  return (
    <div className="flex flex-col gap-2">
      {policies.map((p) => <PolicyRuleCard key={p.id} policy={p} />)}
      {hasNextPage && (
        <div className="flex justify-center pt-1">
          <Button variant="outline" size="sm" onClick={() => void fetchNextPage()}
            disabled={isFetchingNextPage} className="h-7 text-compact">
            {isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
