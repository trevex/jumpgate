/**
 * capability-input.tsx — a controlled tag-input for capability strings.
 *
 * The caller owns the value (an array of capability strings). Typing a
 * capability and pressing Enter (or comma) validates it against the server's
 * glob grammar (`isValidCapability`) and, if valid and not already present,
 * appends it as a removable chip. Invalid input is rejected with an inline
 * hint; duplicates are silently ignored. A muted "vocabulary" reference lists
 * the common capability families so operators don't have to memorise them.
 *
 * `isValidCapability` is exported (and unit-tested) so the create dialog can
 * gate its submit on "at least one valid capability".
 */

import { useState } from "react";
import { X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/**
 * Mirrors the server's stored-capability glob grammar (protovalidate on
 * CreateRoleRequest.capabilities). A capability is either the bare "**", or a
 * colon-delimited scoped path (≥2 segments) where each non-final segment is a
 * lowercase-alphanumeric token with internal hyphens or a single-segment "*",
 * and the final segment additionally allows a trailing "**".
 */
const CAPABILITY_RE =
  /^(\*\*|([a-z0-9]+(-[a-z0-9]+)*|\*)(:([a-z0-9]+(-[a-z0-9]+)*|\*))*:([a-z0-9]+(-[a-z0-9]+)*|\*|\*\*))$/;

/** Pure validator — true when `s` is a well-formed capability pattern. */
export function isValidCapability(s: string): boolean {
  return CAPABILITY_RE.test(s.trim());
}

/** Common capability families, summarised from docs/capabilities.md. */
const VOCABULARY: { pattern: string; note: string }[] = [
  { pattern: "catalog:asset:*", note: "onboard / read / update assets" },
  { pattern: "access:role:*", note: "manage roles & grant edges" },
  { pattern: "identity:user:*", note: "manage directory users" },
  { pattern: "ssh:login:<login>", note: "connect as a target login" },
  { pattern: "recording:read", note: "view session recordings" },
  { pattern: "**", note: "everything (super-admin)" },
];

interface CapabilityInputProps {
  value: string[];
  onChange: (next: string[]) => void;
  id?: string;
}

const FIELD_HINT = "text-[11px] text-muted-foreground";
const FIELD_ERROR = "text-[11px] text-destructive";

export function CapabilityInput({ value, onChange, id }: CapabilityInputProps) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  function commit() {
    const cap = draft.trim();
    if (cap === "") return;
    if (!isValidCapability(cap)) {
      setError(
        "Not a valid capability. Use scope:action[:qualifier] (lowercase), e.g. ssh:login:deploy.",
      );
      return;
    }
    if (!value.includes(cap)) {
      onChange([...value, cap]);
    }
    setDraft("");
    setError(null);
  }

  function remove(cap: string) {
    onChange(value.filter((c) => c !== cap));
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit();
    } else if (e.key === "Backspace" && draft === "" && value.length > 0) {
      // Backspace on an empty field removes the last chip (a common tag-input UX).
      remove(value[value.length - 1]!);
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((cap) => (
            <Badge
              key={cap}
              variant="secondary"
              className="gap-1 rounded px-1.5 py-0.5 font-mono text-[11px] font-medium"
            >
              {cap}
              <button
                type="button"
                onClick={() => remove(cap)}
                aria-label={`Remove ${cap}`}
                className="ml-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3 w-3" aria-hidden="true" />
              </button>
            </Badge>
          ))}
        </div>
      )}

      <Input
        id={id}
        type="text"
        autoComplete="off"
        spellCheck={false}
        value={draft}
        onChange={(e) => {
          setDraft(e.target.value);
          if (error) setError(null);
        }}
        onKeyDown={handleKeyDown}
        onBlur={commit}
        placeholder="ssh:login:deploy — press Enter to add"
        className={cn("h-9 font-mono text-[13px]", error && "border-destructive")}
        aria-invalid={error != null}
      />

      {error ? (
        <p className={FIELD_ERROR}>{error}</p>
      ) : (
        <p className={FIELD_HINT}>
          Press Enter or comma to add. Type a scoped capability like{" "}
          <span className="font-mono">scope:action:qualifier</span>.
        </p>
      )}

      {/* Vocabulary reference — the common families, so operators don't memorise. */}
      <details className="mt-1 rounded border border-border bg-muted/30 px-2.5 py-1.5">
        <summary className="cursor-pointer select-none text-[11px] font-medium text-muted-foreground">
          Common capabilities
        </summary>
        <ul className="mt-1.5 flex flex-col gap-1">
          {VOCABULARY.map((v) => (
            <li key={v.pattern} className="flex items-baseline gap-2 text-[11px]">
              <code className="shrink-0 font-mono text-foreground">{v.pattern}</code>
              <span className="text-muted-foreground">{v.note}</span>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}
