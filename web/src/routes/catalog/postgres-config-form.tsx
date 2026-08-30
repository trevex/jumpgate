/**
 * postgres-config-form.tsx — the shared PostgreSQL connection + auth editor.
 *
 * Mirror of asset-config-form.tsx (SSH) for postgres assets: a target host:port,
 * a default database, an optional pinned target server CA (PEM; empty =
 * encryption-only), and a list of DB-role logins. Each login carries a role, an
 * auth kind (mtls | password), and — for password — a write-only secret. mtls
 * needs no secret (the broker mints a short-lived client cert per session).
 *
 * buildPostgresConfigInput is the pure draft → PostgresConfigInput translator
 * (create/edit secret rules in one place), used by the create wizard and the
 * detail edit dialog.
 */

import type { MessageInitShape } from "@bufbuild/protobuf";
import type { PostgresConfig } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import { PostgresConfigInputSchema } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, Trash2 } from "lucide-react";

export type PgLoginKind = "mtls" | "password";

export interface PgLoginDraft {
  role: string;
  kind: PgLoginKind;
  /** Plaintext the user typed. Empty = "keep existing" in edit mode. */
  secret: string;
  /** Present in edit mode for a pre-existing password login. */
  existingSecretId?: string;
}

export interface PgConfigDraft {
  targetAddress: string;
  defaultDatabase: string;
  targetServerCa: string;
  logins: PgLoginDraft[];
}

const KINDS: readonly PgLoginKind[] = ["mtls", "password"];
const KIND_LABEL: Record<PgLoginKind, string> = {
  mtls: "mTLS (client cert)",
  password: "Password",
};

/** A fresh draft: one empty mtls login row (the common case, no secret needed). */
export function emptyPgDraft(): PgConfigDraft {
  return {
    targetAddress: "",
    defaultDatabase: "",
    targetServerCa: "",
    logins: [{ role: "", kind: "mtls", secret: "" }],
  };
}

/** Map a read-side PostgresConfig into an editable draft. Secrets are never
 *  echoed back, so each password login keeps only its `existingSecretId`. */
export function pgDraftFromAsset(pg: PostgresConfig): PgConfigDraft {
  return {
    targetAddress: pg.targetAddress,
    defaultDatabase: pg.defaultDatabase,
    targetServerCa: pg.targetServerCa,
    logins: pg.logins.map((l) => {
      const kind = (l.kind as PgLoginKind) ?? "mtls";
      return {
        role: l.role,
        kind: KINDS.includes(kind) ? kind : "mtls",
        secret: "",
        existingSecretId: l.kind === "password" ? l.secretId || undefined : undefined,
      };
    }),
  };
}

export type PostgresConfigInputInit = MessageInitShape<typeof PostgresConfigInputSchema>;
type PgLoginInputInit = NonNullable<PostgresConfigInputInit["logins"]>[number];

export function buildPostgresConfigInput(
  draft: PgConfigDraft,
  mode: "create" | "edit",
): { config: PostgresConfigInputInit; error?: string } {
  const logins: PgLoginInputInit[] = [];

  for (const l of draft.logins) {
    const role = l.role.trim();
    if (role.length === 0) {
      return { config: emptyInput(), error: "every login needs a role" };
    }

    if (l.kind === "mtls") {
      logins.push({ role, auth: { case: "mtls", value: {} } });
      continue;
    }

    // password
    if (l.secret.length > 0) {
      logins.push({
        role,
        auth: {
          case: "password",
          value: { source: { case: "newValue", value: new TextEncoder().encode(l.secret) } },
        },
      });
    } else if (mode === "edit" && l.existingSecretId) {
      logins.push({
        role,
        auth: {
          case: "password",
          value: { source: { case: "existingSecretId", value: l.existingSecretId } },
        },
      });
    } else {
      return { config: emptyInput(), error: `login ${role}: a password is required` };
    }
  }

  return {
    config: {
      logins,
      targetAddress: draft.targetAddress.trim(),
      targetServerCa: draft.targetServerCa.trim(),
      defaultDatabase: draft.defaultDatabase.trim(),
    },
  };
}

function emptyInput(): PostgresConfigInputInit {
  return { logins: [], targetAddress: "", targetServerCa: "", defaultDatabase: "" };
}

interface PostgresConfigFormProps {
  mode: "create" | "edit";
  value: PgConfigDraft;
  onChange: (next: PgConfigDraft) => void;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";

export function PostgresConfigForm({ value, onChange }: PostgresConfigFormProps) {
  function patch(next: Partial<PgConfigDraft>) {
    onChange({ ...value, ...next });
  }
  function patchLogin(index: number, next: Partial<PgLoginDraft>) {
    onChange({ ...value, logins: value.logins.map((l, i) => (i === index ? { ...l, ...next } : l)) });
  }
  function addLogin() {
    onChange({ ...value, logins: [...value.logins, { role: "", kind: "mtls", secret: "" }] });
  }
  function removeLogin(index: number) {
    onChange({ ...value, logins: value.logins.filter((_, i) => i !== index) });
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Target address */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="pg-target" className={FIELD_LABEL}>Target address</label>
        <Input
          id="pg-target"
          type="text"
          autoComplete="off"
          value={value.targetAddress}
          onChange={(e) => patch({ targetAddress: e.target.value })}
          placeholder="pg-primary.internal:5432"
          className="h-9 font-mono text-body"
        />
        <p className={FIELD_HINT}>host:port the worker dials (TLS required on the target).</p>
      </div>

      {/* Default database */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="pg-db" className={FIELD_LABEL}>Default database</label>
        <Input
          id="pg-db"
          type="text"
          autoComplete="off"
          value={value.defaultDatabase}
          onChange={(e) => patch({ defaultDatabase: e.target.value })}
          placeholder="appdb"
          className="h-9 font-mono text-body"
        />
        <p className={FIELD_HINT}>Database used when the client omits one.</p>
      </div>

      {/* Target server CA */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="pg-ca" className={FIELD_LABEL}>Target server CA</label>
        <textarea
          id="pg-ca"
          autoComplete="off"
          value={value.targetServerCa}
          onChange={(e) => patch({ targetServerCa: e.target.value })}
          placeholder="-----BEGIN CERTIFICATE-----\n…"
          rows={2}
          className="min-h-[3.5rem] w-full resize-y rounded-md border border-input bg-transparent px-3 py-2 font-mono text-micro shadow-xs transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        <p className={FIELD_HINT}>Optional PEM to pin the target's TLS cert (verify-full); empty = encryption-only.</p>
      </div>

      {/* Logins */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className={FIELD_LABEL}>Logins</span>
          <Button type="button" variant="outline" size="sm" onClick={addLogin} className="h-7 gap-1 text-compact">
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            Add login
          </Button>
        </div>

        {value.logins.length === 0 ? (
          <p className={FIELD_HINT}>No logins yet. Add at least one DB role to onboard the asset.</p>
        ) : (
          <ul className="flex flex-col gap-2" aria-label="Postgres logins">
            {value.logins.map((l, i) => {
              const keepsExisting = Boolean(l.existingSecretId) && l.secret.length === 0;
              return (
                <li key={i} className="flex flex-col gap-2 rounded-md border border-border p-2.5">
                  <div className="flex items-start gap-2">
                    <Input
                      type="text"
                      autoComplete="off"
                      value={l.role}
                      onChange={(e) => patchLogin(i, { role: e.target.value })}
                      placeholder="app"
                      aria-label={`Role for row ${i + 1}`}
                      className="h-8 flex-1 font-mono text-body"
                    />
                    <Select value={l.kind} onValueChange={(v) => patchLogin(i, { kind: v as PgLoginKind })}>
                      <SelectTrigger aria-label={`Auth kind for row ${i + 1}`} className="h-8 w-[160px] text-body">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {KINDS.map((k) => (
                          <SelectItem key={k} value={k} className="text-body">{KIND_LABEL[k]}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => removeLogin(i)}
                      className="h-8 w-8 shrink-0 text-muted-foreground hover:text-destructive"
                      aria-label={`Remove login row ${i + 1}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                    </Button>
                  </div>

                  {l.kind === "password" && (
                    <Input
                      type="password"
                      autoComplete="new-password"
                      value={l.secret}
                      onChange={(e) => patchLogin(i, { secret: e.target.value })}
                      placeholder={keepsExisting ? "•••••• (unchanged)" : "Password"}
                      aria-label={`Password for row ${i + 1}`}
                      className="h-8 text-body"
                    />
                  )}
                </li>
              );
            })}
          </ul>
        )}
        <p className={FIELD_HINT}>
          mTLS logins use short-lived client certs (no secret). Password logins store a sealed
          secret; leave it blank when editing to keep the current one.
        </p>
      </div>
    </div>
  );
}
