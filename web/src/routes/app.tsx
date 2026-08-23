import { useState } from "react";
import { Outlet, NavLink, useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import {
  LayoutDashboard,
  LayoutGrid,
  KeyRound,
  ClipboardCheck,
  Film,
  UsersRound,
  LogOut,
  ShieldCheck,
  Search,
} from "lucide-react";
import { logout } from "../gen/jumpgate/auth/v1/auth-AuthService_connectquery";
import { listPendingApprovals } from "../gen/jumpgate/accessrequest/v1/accessrequest-AccessRequestService_connectquery";
import { useWhoAmI } from "../auth";
import { capsCover, useCapabilities } from "../lib/capabilities";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "../components/ui/tooltip";
import { ThemeToggle } from "../components/theme-toggle";
import { SearchPalette, useCommandK } from "../components/search-palette";
import { Logo } from "../components/brand/logo";
import { cn } from "../lib/utils";

// ─── Pending-approvals badge count ──────────────────────────────────────────

function usePendingCount(): number {
  const { data } = useQuery(listPendingApprovals, { pageSize: 100 });
  return data?.requests.length ?? 0;
}

// ─── Nav item definition ─────────────────────────────────────────────────────

interface NavItem {
  label: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: () => React.ReactNode;
  /** If present, item only renders when this cap is held */
  requiresCap?: string;
  /**
   * If present, item only renders when the caller holds AT LEAST ONE of these
   * caps (OR gate). Composes with `requiresCap` — both must pass when both set.
   */
  requiresAnyCap?: string[];
}

// ─── Sidebar nav link ────────────────────────────────────────────────────────

interface SideNavLinkProps {
  item: NavItem;
  caps: string[];
}

function SideNavLink({ item, caps }: SideNavLinkProps) {
  const pendingCount = usePendingCount();

  if (item.requiresCap != null && !capsCover(caps, item.requiresCap)) {
    return null;
  }

  if (
    item.requiresAnyCap != null &&
    !item.requiresAnyCap.some((cap) => capsCover(caps, cap))
  ) {
    return null;
  }

  return (
    <NavLink
      to={item.to}
      end={item.to === "/"}
      className={({ isActive }) =>
        cn(
          "group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
          isActive
            ? "bg-primary/10 text-primary"
            : "text-muted-foreground hover:bg-accent hover:text-foreground",
        )
      }
      aria-label={item.label}
    >
      <item.icon className="h-4 w-4 shrink-0" />
      <span className="flex-1 truncate">{item.label}</span>
      {item.label === "Approvals" && pendingCount > 0 && (
        <Badge
          variant="default"
          className="ml-auto h-5 min-w-5 rounded-full px-1.5 text-eyebrow font-semibold leading-none"
          aria-label={`${pendingCount} pending approval${pendingCount !== 1 ? "s" : ""}`}
        >
          {pendingCount > 99 ? "99+" : pendingCount}
        </Badge>
      )}
    </NavLink>
  );
}

// ─── User avatar / initials ───────────────────────────────────────────────────

function UserInitials({ email }: { email: string }) {
  const initial = email.charAt(0).toUpperCase();
  return (
    <span
      aria-hidden="true"
      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-micro font-semibold text-primary"
    >
      {initial}
    </span>
  );
}

// ─── AppShell ────────────────────────────────────────────────────────────────

const NAV_ITEMS: NavItem[] = [
  {
    label: "Home",
    to: "/",
    icon: LayoutDashboard,
  },
  {
    label: "Catalog",
    to: "/catalog",
    icon: LayoutGrid,
  },
  {
    label: "My Access",
    to: "/access",
    icon: KeyRound,
  },
  {
    label: "Approvals",
    to: "/approvals",
    icon: ClipboardCheck,
  },
  {
    label: "Directory",
    to: "/directory",
    icon: UsersRound,
    requiresAnyCap: ["identity:user:read", "identity:group:read"],
  },
  {
    label: "Access control",
    to: "/access-control",
    icon: ShieldCheck,
    requiresAnyCap: [
      "access:role:read",
      "access:binding:read",
      "access:policy:read",
    ],
  },
  {
    label: "Recordings",
    to: "/recordings",
    icon: Film,
    requiresCap: "recording:read",
  },
];

export function AppShell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: whoAmI } = useWhoAmI();
  const caps = useCapabilities();
  const [searchOpen, setSearchOpen] = useState(false);
  useCommandK(() => setSearchOpen(true));

  const { mutate: doLogout, isPending: isLoggingOut } = useMutation(logout, {
    onSuccess: () => {
      queryClient.clear();
      navigate("/login");
    },
  });

  const email = whoAmI?.email ?? "";

  return (
    <TooltipProvider delayDuration={300}>
      {/* Skip-to-main for keyboard/screen-reader users */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-4 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:ring-2 focus:ring-ring"
      >
        Skip to main content
      </a>

      <div className="flex h-screen overflow-hidden bg-background">
        {/* ── Sidebar ── */}
        <aside
          className="flex w-56 shrink-0 flex-col border-r border-border bg-sidebar"
          aria-label="Primary navigation"
        >
          {/* Brand */}
          <div className="flex h-14 items-center border-b border-border px-4">
            <Logo markClassName="h-5 w-5" wordmarkClassName="text-sm" />
          </div>

          {/* Nav */}
          <nav className="flex-1 overflow-y-auto px-2 py-3">
            <ul className="flex flex-col gap-0.5" role="list">
              {NAV_ITEMS.map((item) => (
                <li key={item.to}>
                  <SideNavLink item={item} caps={caps} />
                </li>
              ))}
            </ul>
          </nav>

          {/* User footer */}
          <div className="border-t border-border px-2 py-3">
            <div className="flex items-center gap-2 rounded-md px-2 py-1.5">
              <UserInitials email={email} />
              <Tooltip>
                <TooltipTrigger asChild>
                  <span
                    className="flex-1 truncate text-xs text-muted-foreground cursor-default"
                    aria-label={`Signed in as ${email}`}
                  >
                    {email}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="right" className="text-xs">
                  {email}
                </TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 shrink-0 text-muted-foreground hover:text-destructive"
                    onClick={() => doLogout({})}
                    disabled={isLoggingOut}
                    aria-label="Sign out"
                  >
                    <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right" className="text-xs">
                  Sign out
                </TooltipContent>
              </Tooltip>
            </div>
          </div>
        </aside>

        {/* ── Main content ── */}
        <div className="flex flex-1 flex-col overflow-hidden">
          {/* Top bar */}
          <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-background px-6">
            {/* Page title injected by child route via context / future enhancement */}
            <span className="text-sm text-muted-foreground">
              Privileged access management
            </span>
            {/* Right cluster — catalog search + theme toggle */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setSearchOpen(true)}
                aria-label="Search catalog"
                className={cn(
                  "group inline-flex h-8 items-center gap-2 rounded-md border border-border bg-muted/40 pl-2.5 pr-1.5 text-sm text-muted-foreground transition-colors",
                  "hover:bg-accent hover:text-foreground",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                )}
              >
                <Search className="h-3.5 w-3.5" aria-hidden="true" />
                <span className="hidden sm:inline">Search…</span>
                <kbd
                  aria-hidden="true"
                  className="ml-1 hidden items-center gap-0.5 rounded border border-border bg-background px-1.5 font-mono text-eyebrow font-medium text-muted-foreground sm:inline-flex"
                >
                  ⌘K
                </kbd>
              </button>
              <ThemeToggle />
            </div>
          </header>

          {/* Scrollable page area */}
          <main
            id="main-content"
            className="flex-1 overflow-y-auto"
            tabIndex={-1}
          >
            <Outlet />
          </main>
        </div>
      </div>

      {/* Global ⌘K command palette — available on every route */}
      <SearchPalette open={searchOpen} onOpenChange={setSearchOpen} />
    </TooltipProvider>
  );
}
