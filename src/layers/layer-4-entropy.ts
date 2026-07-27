// Layer 4: Shannon-Entropy-Heuristik
// Erkennt hoch-entropy Strings in isolierten Tokens

import type { Match, RedactionContext, LayerResult } from "../types.js";
import { buildMarker, buildMarkerCache, isInsideMarker } from "./shared.js";

/**
 * Calculate Shannon entropy in bits per character.
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of str) {
    freq.set(c, (freq.get(c) || 0) + 1);
  }
  let h = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const HEX_RE = /^[A-Fa-f0-9]+$/;
const BASE64_RE = /^[A-Za-z0-9+/=]+$/;
const TOKEN_RE = /\b[A-Za-z0-9+/\-_]{20,}\b/g;

const ALLOWLIST_DEFAULT_PATTERNS = [
  // Git short SHAs
  /\b[0-9a-f]{7,40}\b.*?(?:commit|sha)/i,
  // UUIDs
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i,
  // Semver
  /\bv?\d+\.\d+\.\d+(?:-[\w.]+)?\b/,
];

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = [];
  const minEntropy = ctx.config.minEntropy;
  const minLength = ctx.config.minLength;

  // Combine default + user allowlist patterns
  const userPatterns = ctx.config.allowlistRegex
    .map((p) => {
      try {
        return new RegExp(p);
      } catch {
        return null;
      }
    })
    .filter((p): p is RegExp => p !== null);
  const allowlistPatterns = [...ALLOWLIST_DEFAULT_PATTERNS, ...userPatterns];

  // PERFORMANCE FIX: Build marker cache once, not per-match
  const markerCache = buildMarkerCache(text);

  TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(text)) !== null) {
    const value = m[0];
    const start = m.index;
    const end = start + value.length;

    if (value.length < minLength) continue;
    // O(log n) marker check instead of O(n)
    if (isInsideMarker(markerCache, start, end)) continue;
    // Tokens at the same position will have the same start — but each match is unique
    // because regex.exec advances. So O(n) overlap check is actually O(1) amortized
    // since most new matches are far apart from previous ones.
    // Still, we keep it for correctness — it's not the bottleneck for normal inputs.

    // Token must look like base64 or hex
    const isHex = HEX_RE.test(value);
    const isBase64 = BASE64_RE.test(value);
    if (!isHex && !isBase64) continue;

    // Allowlist check: if any allowlist pattern matches, skip
    let allowed = false;
    for (const p of allowlistPatterns) {
      if (p.test(value)) {
        allowed = true;
        break;
      }
    }
    if (allowed) continue;

    const entropy = shannonEntropy(value);
    if (entropy < minEntropy) continue;

    matches.push({
      start,
      end,
      type: "High Entropy Token",
      replacement: buildMarker(value, "High Entropy Token", ctx.config.preservePrefixChars, ctx.config.asterisksMax),
    });
  }

  return { matches };
}