/**
 * rdp-config-form.tsx — the shared RDP connection + auth editor.
 *
 * Mirror of postgres-config-form.tsx for RDP assets, simplified: RDP has a
 * single auth kind (password — smartcard/cert is a future kind, see
 * RDPLoginInput), so each login row is just {login, password}. No default
 * database, no mtls toggle.
 *
 * buildRdpConfigInput is the pure draft → RDPConfigInput translator
 * (create/edit secret rules in one place), used by the create wizard and the
 * detail edit dialog.
 */

import type { MessageInitShape } from "@bufbuild/protobuf";
import type { RDPConfig } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import { RDPConfigInputSchema } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, Trash2 } from "lucide-react";

export interface RdpLoginDraft {
  login: string;
  /** Plaintext the user typed. Empty = "keep existing" in edit mode. */
  secret: string;
  /** Present in edit mode for a pre-existing login. */
  existingSecretId?: string;
}

export interface RdpConfigDraft {
  targetAddress: string;
  targetServerCa: string;
  logins: RdpLoginDraft[];
}

/** A fresh draft: one empty login row. */
export function emptyRdpDraft(): RdpConfigDraft {
  return {
    targetAddress: "",
    targetServerCa: "",
    logins: [{ login: "", secret: "" }],
  };
}

/** Map a read-side RDPConfig into an editable draft. Secrets are never
 *  echoed back, so each login keeps only its `existingSecretId`. */
export function rdpDraftFromAsset(rdp: RDPConfig): RdpConfigDraft {
  return {
    targetAddress: rdp.targetAddress,
    targetServerCa: rdp.targetServerCa,
    logins: rdp.logins.map((l) => ({
      login: l.login,
      secret: "",
      existingSecretId: l.secretId || undefined,
    })),
  };
}

export type RDPConfigInputInit = MessageInitShape<typeof RDPConfigInputSchema>;
type RdpLoginInputInit = NonNullable<RDPConfigInputInit["logins"]>[number];

export function buildRdpConfigInput(
  draft: RdpConfigDraft,
  mode: "create" | "edit",
): { config: RDPConfigInputInit; error?: string } {
  const logins: RdpLoginInputInit[] = [];

  for (const l of draft.logins) {
    const login = l.login.trim();
    if (login.length === 0) {
      return { config: emptyInput(), error: "every login needs a login name" };
    }

    if (l.secret.length > 0) {
      logins.push({
        login,
        auth: {
          case: "password",
          value: { source: { case: "newValue", value: new TextEncoder().encode(l.secret) } },
        },
      });
    } else if (mode === "edit" && l.existingSecretId) {
      logins.push({
        login,
        auth: {
          case: "password",
          value: { source: { case: "existingSecretId", value: l.existingSecretId } },
        },
      });
    } else {
      return { config: emptyInput(), error: `login ${login}: a password is required` };
    }
  }

  return {
    config: {
      logins,
      targetAddress: draft.targetAddress.trim(),
      targetServerCa: draft.targetServerCa.trim(),
    },
  };
}

function emptyInput(): RDPConfigInputInit {
  return { logins: [], targetAddress: "", targetServerCa: "" };
}

interface RdpConfigFormProps {
  mode: "create" | "edit";
  value: RdpConfigDraft;
  onChange: (next: RdpConfigDraft) => void;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";

export function RdpConfigForm({ value, onChange }: RdpConfigFormProps) {
  function patch(next: Partial<RdpConfigDraft>) {
    onChange({ ...value, ...next });
  }
  function patchLogin(index: number, next: Partial<RdpLoginDraft>) {
    onChange({ ...value, logins: value.logins.map((l, i) => (i === index ? { ...l, ...next } : l)) });
  }
  function addLogin() {
    onChange({ ...value, logins: [...value.logins, { login: "", secret: "" }] });
  }
  function removeLogin(index: number) {
    onChange({ ...value, logins: value.logins.filter((_, i) => i !== index) });
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Target address */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="rdp-target" className={FIELD_LABEL}>Target address</label>
        <Input
          id="rdp-target"
          type="text"
          autoComplete="off"
          value={value.targetAddress}
          onChange={(e) => patch({ targetAddress: e.target.value })}
          placeholder="win-host.internal:3389"
          className="h-9 font-mono text-body"
        />
        <p className={FIELD_HINT}>host:port the worker dials (RDP default 3389).</p>
      </div>

      {/* Target server CA */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="rdp-ca" className={FIELD_LABEL}>Target server CA</label>
        <textarea
          id="rdp-ca"
          autoComplete="off"
          value={value.targetServerCa}
          onChange={(e) => patch({ targetServerCa: e.target.value })}
          placeholder="-----BEGIN CERTIFICATE-----\n…"
          rows={2}
          className="min-h-[3.5rem] w-full resize-y rounded-md border border-input bg-transparent px-3 py-2 font-mono text-micro shadow-xs transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        <p className={FIELD_HINT}>Optional PEM to pin the target's TLS cert; empty = require-TLS without pin.</p>
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
          <p className={FIELD_HINT}>No logins yet. Add at least one account to onboard the asset.</p>
        ) : (
          <ul className="flex flex-col gap-2" aria-label="RDP logins">
            {value.logins.map((l, i) => {
              const keepsExisting = Boolean(l.existingSecretId) && l.secret.length === 0;
              return (
                <li key={i} className="flex flex-col gap-2 rounded-md border border-border p-2.5">
                  <div className="flex items-start gap-2">
                    <Input
                      type="text"
                      autoComplete="off"
                      value={l.login}
                      onChange={(e) => patchLogin(i, { login: e.target.value })}
                      placeholder="administrator"
                      aria-label={`Login for row ${i + 1}`}
                      className="h-8 flex-1 font-mono text-body"
                    />
                    <Input
                      type="password"
                      autoComplete="new-password"
                      value={l.secret}
                      onChange={(e) => patchLogin(i, { secret: e.target.value })}
                      placeholder={keepsExisting ? "•••••• (unchanged)" : "Password"}
                      aria-label={`Password for row ${i + 1}`}
                      className="h-8 flex-1 text-body"
                    />
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
                </li>
              );
            })}
          </ul>
        )}
        <p className={FIELD_HINT}>
          Logins store a sealed password; leave it blank when editing to keep the current one.
        </p>
      </div>
    </div>
  );
}
