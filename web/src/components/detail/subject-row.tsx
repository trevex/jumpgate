import { User, Users } from "lucide-react";
import { cn } from "@/lib/utils";

export interface SubjectRowProps {
  name: string;
  kind: string; // "user" | "group"
  /** Secondary text, e.g. scope path or roster detail. */
  detail?: string;
  inactive?: boolean;
  className?: string;
}

/** One subject line: glyph + name + secondary detail. Shared by held-by, roster,
 *  bindings, and policy-participation lists. */
export function SubjectRow({ name, kind, detail, inactive, className }: SubjectRowProps) {
  const Icon = kind === "group" ? Users : User;
  return (
    <div className={cn("flex items-center justify-between gap-3 px-1 py-1.5", className)}>
      <span className="inline-flex min-w-0 items-center gap-1.5">
        <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span className={cn("truncate text-compact font-medium text-foreground", inactive && "line-through opacity-60")} title={name}>
          {name}
        </span>
      </span>
      {detail && <span className="shrink-0 text-micro text-muted-foreground">{detail}</span>}
    </div>
  );
}
