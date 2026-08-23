/**
 * format.ts — shared time/duration formatting helpers.
 *
 * Keeps date arithmetic out of components and makes it easy to test.
 */

import { ConnectError } from "@connectrpc/connect";

// ─── Relative time ────────────────────────────────────────────────────────────

/**
 * Returns a short human-readable relative-time string, e.g. "3 minutes ago",
 * "in 2 hours", or "just now". All arithmetic is done against Date.now() so
 * it works correctly for both past and future timestamps.
 */
export function relativeTime(rfc3339: string): string {
  if (!rfc3339) return "";
  const ts = Date.parse(rfc3339);
  if (isNaN(ts)) return rfc3339;

  const diffMs = ts - Date.now();
  const absMs = Math.abs(diffMs);
  const past = diffMs < 0;

  let value: number;
  let unit: string;

  if (absMs < 60_000) {
    return "just now";
  } else if (absMs < 3_600_000) {
    value = Math.floor(absMs / 60_000);
    unit = value === 1 ? "minute" : "minutes";
  } else if (absMs < 86_400_000) {
    value = Math.floor(absMs / 3_600_000);
    unit = value === 1 ? "hour" : "hours";
  } else if (absMs < 7 * 86_400_000) {
    value = Math.floor(absMs / 86_400_000);
    unit = value === 1 ? "day" : "days";
  } else {
    value = Math.floor(absMs / (7 * 86_400_000));
    unit = value === 1 ? "week" : "weeks";
  }

  return past ? `${value} ${unit} ago` : `in ${value} ${unit}`;
}

// ─── Duration remaining ───────────────────────────────────────────────────────

/**
 * Returns how much time remains until an RFC3339 expiry string, e.g.
 * "47m", "3h 12m", "2d 4h". Returns "expired" when the timestamp is in
 * the past.
 */
export function timeRemaining(expiresAt: string): string {
  if (!expiresAt) return "";
  const ts = Date.parse(expiresAt);
  if (isNaN(ts)) return expiresAt;

  const diffMs = ts - Date.now();
  if (diffMs <= 0) return "expired";

  const totalSeconds = Math.floor(diffMs / 1000);
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);

  if (days > 0) {
    return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  }
  if (hours > 0) {
    return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
  }
  return `${minutes}m`;
}

/**
 * Returns true when an RFC3339 timestamp is in the past.
 */
export function isExpired(rfc3339: string): boolean {
  if (!rfc3339) return false;
  return Date.parse(rfc3339) <= Date.now();
}

// ─── Identifier shortening ────────────────────────────────────────────────────

/**
 * Returns the first dash-delimited segment of an identifier (typically the
 * leading block of a UUID), falling back to the full id when it contains no
 * dash.
 */
export function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

// ─── ConnectError message extraction ─────────────────────────────────────────

/**
 * Extracts a human-readable message from any error thrown by a Connect RPC.
 * Falls back to the raw string for non-Connect errors.
 */
export function connectErrorMessage(err: unknown): string {
  return ConnectError.from(err).message;
}
