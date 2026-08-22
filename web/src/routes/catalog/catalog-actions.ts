/**
 * catalog-actions.ts — pure gating + validation logic for catalog authoring.
 *
 * Decides which folder/asset authoring affordances to offer given the caller's
 * capabilities, and validates catalog names. The server is the real gate; this
 * only governs which controls are shown.
 *
 *   - Folder create/update/delete: `catalog:folder:{create,update,delete}`.
 *   - Asset  create/update/delete: `catalog:asset:{create,update,delete}`.
 *
 * Catalog names mirror the sibling-uniqueness registry charset `^[a-z0-9_-]+$`
 * (the registry case-folds the proto's `^[a-zA-Z0-9_-]+$`), matching how the
 * directory validates group names.
 */

import { capsCover } from "@/lib/capabilities";

export const canCreateFolder = (c: string[]) => capsCover(c, "catalog:folder:create");
export const canUpdateFolder = (c: string[]) => capsCover(c, "catalog:folder:update");
export const canDeleteFolder = (c: string[]) => capsCover(c, "catalog:folder:delete");
export const canCreateAsset = (c: string[]) => capsCover(c, "catalog:asset:create");
export const canUpdateAsset = (c: string[]) => capsCover(c, "catalog:asset:update");
export const canDeleteAsset = (c: string[]) => capsCover(c, "catalog:asset:delete");

const NAME_RE = /^[a-z0-9_-]+$/;

export const isValidCatalogName = (n: string): boolean => {
  const t = n.trim();
  return t.length >= 1 && t.length <= 200 && NAME_RE.test(t);
};
