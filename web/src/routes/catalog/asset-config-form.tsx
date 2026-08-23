/**
 * asset-config-form.tsx — the shared SSH connection + auth editor.
 *
 * A controlled editor for an asset's SSH config: a target `host:port`, an
 * optional pinned host public key, and a list of logins. Each login carries a
 * name, an auth kind (ca | password | key), and — for password/key — a
 * write-only secret. The parent owns the `ConfigDraft` and receives changes via
 * `onChange`; this component renders no mutation of its own.
 *
 * Secrets are write-only: reads never return the bytes, so an edit-mode row
 * that already references a stored secret shows a "•••••• (unchanged)"
 * placeholder. Leaving that secret empty keeps the existing sealed value
 * (`existingSecretId`); typing a new value rotates it (`newValue`, sealed
 * server-side in-tx). In create mode every password/key login must carry a
 * secret.
 *
 * `buildSSHConfigInput` is the pure translator from draft → the write-only
 * `SSHConfigInput` message value (for `config: { case: "ssh", value }`), or a
 * human-readable validation error. Both the create wizard and the detail edit
 * dialog use it, so the create/edit secret rules live in exactly one place.
 */

import type { MessageInitShape } from "@bufbuild/protobuf";
import type { SSHConfig } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import { SSHConfigInputSchema } from "@/gen/jumpgate/catalog/v1/catalog_pb";
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

// ─── Draft model (owned by the parent) ────────────────────────────────────────

export type LoginKind = "ca" | "password" | "key";

export interface LoginDraft {
  login: string;
  kind: LoginKind;
  /** Plaintext the user typed. Empty = "keep existing" in edit mode. */
  secret: string;
  /** Present in edit mode for a pre-existing password/key login. */
  existingSecretId?: string;
}

export interface ConfigDraft {
  targetAddress: string;
  hostPublicKey: string;
  logins: LoginDraft[];
}

const KINDS: readonly LoginKind[] = ["ca", "password", "key"];

const KIND_LABEL: Record<LoginKind, string> = {
  ca: "CA (signed cert)",
  password: "Password",
  key: "Private key",
};

// ─── Draft factories ──────────────────────────────────────────────────────────

/** A fresh draft: one empty CA login row (the common case, no secret needed). */
export function emptyDraft(): ConfigDraft {
  return {
    targetAddress: "",
    hostPublicKey: "",
    logins: [{ login: "", kind: "ca", secret: "" }],
  };
}

/** Map a read-side SSHConfig into an editable draft. Secrets are never echoed
 *  back, so each password/key login keeps only its `existingSecretId` and an
 *  empty `secret` (meaning "unchanged" until the user types a replacement). */
export function draftFromAsset(ssh: SSHConfig): ConfigDraft {
  return {
    targetAddress: ssh.targetAddress,
    hostPublicKey: ssh.hostPublicKey,
    logins: ssh.logins.map((l) => {
      const kind = (l.kind as LoginKind) ?? "ca";
      return {
        login: l.login,
        kind: KINDS.includes(kind) ? kind : "ca",
        secret: "",
        existingSecretId: l.kind === "ca" ? undefined : l.secretId || undefined,
      };
    }),
  };
}

// ─── Pure builder: draft → SSHConfigInput | error ─────────────────────────────

/**
 * Translate a draft into the write-only SSHConfigInput value, or return a
 * validation error. The secret rules differ by mode:
 *   - `ca`               → no secret.
 *   - password|key, new  → seal the typed bytes (`newValue`).
 *   - password|key, edit → empty secret keeps the current one (`existingSecretId`).
 *   - password|key, else → error (create, or a new edit row with no secret).
 */
export type SSHConfigInputInit = MessageInitShape<typeof SSHConfigInputSchema>;
type SSHLoginInputInit = NonNullable<SSHConfigInputInit["logins"]>[number];

export function buildSSHConfigInput(
  draft: ConfigDraft,
  mode: "create" | "edit",
): { config: SSHConfigInputInit; error?: string } {
  const logins: SSHLoginInputInit[] = [];

  for (const l of draft.logins) {
    const login = l.login.trim();
    if (login.length === 0) {
      return { config: emptyInput(), error: "every login needs a name" };
    }

    if (l.kind === "ca") {
      logins.push({ login, auth: { case: "ca", value: {} } });
      continue;
    }

    // password | key
    if (l.secret.length > 0) {
      logins.push({
        login,
        auth: {
          case: l.kind,
          value: {
            source: {
              case: "newValue",
              value: new TextEncoder().encode(l.secret),
            },
          },
        },
      });
    } else if (mode === "edit" && l.existingSecretId) {
      logins.push({
        login,
        auth: {
          case: l.kind,
          value: {
            source: { case: "existingSecretId", value: l.existingSecretId },
          },
        },
      });
    } else {
      return { config: emptyInput(), error: `login ${login}: a secret is required` };
    }
  }

  return {
    config: {
      logins,
      hostPublicKey: draft.hostPublicKey.trim(),
      targetAddress: draft.targetAddress.trim(),
    },
  };
}

function emptyInput(): SSHConfigInputInit {
  return { logins: [], hostPublicKey: "", targetAddress: "" };
}

// ─── The controlled editor ────────────────────────────────────────────────────

interface AssetConfigFormProps {
  mode: "create" | "edit";
  value: ConfigDraft;
  onChange: (next: ConfigDraft) => void;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";

export function AssetConfigForm({ value, onChange }: AssetConfigFormProps) {
  function patch(next: Partial<ConfigDraft>) {
    onChange({ ...value, ...next });
  }

  function patchLogin(index: number, next: Partial<LoginDraft>) {
    const logins = value.logins.map((l, i) => (i === index ? { ...l, ...next } : l));
    onChange({ ...value, logins });
  }

  function addLogin() {
    onChange({
      ...value,
      logins: [...value.logins, { login: "", kind: "ca", secret: "" }],
    });
  }

  function removeLogin(index: number) {
    onChange({ ...value, logins: value.logins.filter((_, i) => i !== index) });
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Target address */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="asset-target" className={FIELD_LABEL}>
          Target address
        </label>
        <Input
          id="asset-target"
          type="text"
          autoComplete="off"
          value={value.targetAddress}
          onChange={(e) => patch({ targetAddress: e.target.value })}
          placeholder="db-primary.internal:22"
          className="h-9 font-mono text-body"
        />
        <p className={FIELD_HINT}>
          host:port the worker dials. Empty = worker default resolution.
        </p>
      </div>

      {/* Host public key */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="asset-hostkey" className={FIELD_LABEL}>
          Host public key
        </label>
        <textarea
          id="asset-hostkey"
          autoComplete="off"
          value={value.hostPublicKey}
          onChange={(e) => patch({ hostPublicKey: e.target.value })}
          placeholder="ssh-ed25519 AAAA…"
          rows={2}
          className="min-h-[3.5rem] w-full resize-y rounded-md border border-input bg-transparent px-3 py-2 font-mono text-micro shadow-xs transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        <p className={FIELD_HINT}>
          Optional OpenSSH authorized_keys line. Set = pin the host key; empty =
          accept-and-log.
        </p>
      </div>

      {/* Logins */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className={FIELD_LABEL}>Logins</span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={addLogin}
            className="h-7 gap-1 text-compact"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            Add login
          </Button>
        </div>

        {value.logins.length === 0 ? (
          <p className={FIELD_HINT}>
            No logins yet. Add at least one to onboard the asset.
          </p>
        ) : (
          <ul className="flex flex-col gap-2" aria-label="SSH logins">
            {value.logins.map((l, i) => {
              const needsSecret = l.kind === "password" || l.kind === "key";
              const keepsExisting = Boolean(l.existingSecretId) && l.secret.length === 0;
              return (
                <li
                  key={i}
                  className="flex flex-col gap-2 rounded-md border border-border p-2.5"
                >
                  <div className="flex items-start gap-2">
                    <Input
                      type="text"
                      autoComplete="off"
                      value={l.login}
                      onChange={(e) => patchLogin(i, { login: e.target.value })}
                      placeholder="root"
                      aria-label={`Login name for row ${i + 1}`}
                      className="h-8 flex-1 font-mono text-body"
                    />
                    <Select
                      value={l.kind}
                      onValueChange={(v) =>
                        patchLogin(i, { kind: v as LoginKind })
                      }
                    >
                      <SelectTrigger
                        aria-label={`Auth kind for row ${i + 1}`}
                        className="h-8 w-[150px] text-body"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {KINDS.map((k) => (
                          <SelectItem key={k} value={k} className="text-body">
                            {KIND_LABEL[k]}
                          </SelectItem>
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

                  {needsSecret &&
                    (l.kind === "key" ? (
                      // A private key is multi-line PEM — a textarea, not a
                      // single-line field, so it can be pasted as-is.
                      <textarea
                        autoComplete="off"
                        spellCheck={false}
                        value={l.secret}
                        onChange={(e) => patchLogin(i, { secret: e.target.value })}
                        placeholder={
                          keepsExisting
                            ? "•••••• (unchanged) — paste a new key to rotate"
                            : "-----BEGIN OPENSSH PRIVATE KEY-----\n…"
                        }
                        rows={4}
                        aria-label={`Private key for row ${i + 1}`}
                        className="min-h-[5rem] w-full resize-y rounded-md border border-input bg-transparent px-3 py-2 font-mono text-micro shadow-xs transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      />
                    ) : (
                      <Input
                        type="password"
                        autoComplete="new-password"
                        value={l.secret}
                        onChange={(e) => patchLogin(i, { secret: e.target.value })}
                        placeholder={
                          keepsExisting ? "•••••• (unchanged)" : "Password"
                        }
                        aria-label={`Secret for row ${i + 1}`}
                        className="h-8 text-body"
                      />
                    ))}
                </li>
              );
            })}
          </ul>
        )}
        <p className={FIELD_HINT}>
          CA logins use short-lived signed certs (no secret). Password/key logins
          store a sealed secret; leave it blank when editing to keep the current
          one.
        </p>
      </div>
    </div>
  );
}
