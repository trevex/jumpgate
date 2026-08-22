/**
 * users-tab.tsx — Directory ▸ Users.
 *
 * A keyset-paginated table of directory users (Email, Display name, Status).
 * Status reflects `User.active` (deactivation state) via a colour-coded badge.
 * Loading / empty / error use the shared state components; "Load more" appends
 * the next page. Read-only for now — create + row lifecycle actions land later
 * (see the header action seam below).
 */

import { useState, useEffect, useRef } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { listUsers } from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { User } from "@/gen/jumpgate/identity/v1/identity_pb";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";
import { Users } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Status badge ─────────────────────────────────────────────────────────────

function UserStatusBadge({ active }: { active: boolean }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded px-1.5 py-0 text-[10px] font-semibold uppercase tracking-wide border",
        active
          ? "border-green-300 bg-green-50 text-green-700 dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-300"
          : "border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-500/30 dark:bg-slate-500/10 dark:text-slate-300",
      )}
    >
      {active ? "Active" : "Deactivated"}
    </Badge>
  );
}

// ─── Users tab ────────────────────────────────────────────────────────────────

export function UsersTab() {
  const [pages, setPages] = useState<User[]>([]);
  const [nextToken, setNextToken] = useState<string>("");
  const [loadingMore, setLoadingMore] = useState(false);
  const initialised = useRef(false);

  const { data, isLoading, isError, error, refetch } = useQuery(listUsers, {
    pageSize: PAGE_SIZE,
    pageToken: "",
  });

  // Seed the first page
  useEffect(() => {
    if (data && !initialised.current) {
      initialised.current = true;
      setPages(data.users);
      setNextToken(data.nextPageToken);
    }
  }, [data]);

  // Refresh on query invalidation (mutations land in a later task)
  useEffect(() => {
    if (data && initialised.current) {
      setPages(data.users);
      setNextToken(data.nextPageToken);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.users]);

  const { refetch: fetchMore } = useQuery(
    listUsers,
    { pageSize: PAGE_SIZE, pageToken: nextToken },
    { enabled: false },
  );

  async function loadMore() {
    setLoadingMore(true);
    try {
      const result = await fetchMore();
      if (result.data) {
        setPages((prev) => [...prev, ...result.data!.users]);
        setNextToken(result.data.nextPageToken);
      }
    } finally {
      setLoadingMore(false);
    }
  }

  if (isLoading) return <LoadingRows />;

  if (isError) {
    return (
      <ErrorState
        size="sm"
        message={connectErrorMessage(error)}
        onRetry={() => {
          initialised.current = false;
          refetch();
        }}
      />
    );
  }

  if (pages.length === 0) {
    return <EmptyState icon={Users} message="No users." />;
  }

  return (
    <div className="flex flex-col">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
              Email
            </TableHead>
            <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
              Display name
            </TableHead>
            <TableHead className="h-9 px-4 text-right text-[10px] font-semibold uppercase tracking-widest">
              Status
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {pages.map((user) => (
            <TableRow key={user.id}>
              <TableCell className="px-4 py-2.5 font-medium text-foreground">
                <span className="truncate" title={user.email}>
                  {user.email}
                </span>
              </TableCell>
              <TableCell className="px-4 py-2.5 text-muted-foreground">
                {user.displayName || (
                  <span className="text-muted-foreground/50">—</span>
                )}
              </TableCell>
              <TableCell className="px-4 py-2.5 text-right">
                <UserStatusBadge active={user.active} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {nextToken && (
        <div className="flex justify-center border-t border-border px-4 py-3">
          <Button
            variant="outline"
            size="sm"
            onClick={loadMore}
            disabled={loadingMore}
            className="h-7 text-[12px]"
          >
            {loadingMore ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
