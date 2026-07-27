// Shared utilities for layer implementations

import type { Match } from "../types.js";

/**
 * Build a redaction marker like: `AKIA****************[REDACTED:AWS Access Key]`
 * Preserves a short prefix for context, fills middle with asterisks, appends marker.
 */
export function buildMarker(value: string, type: string, preservePrefixChars = 4, asterisksMax = 20): string {
  // Strip whitespace at boundaries; keep core chars
  const trimmed = value.replace(/^[\s"']+|[\s"']+$/g, "");
  const prefix = trimmed.slice(0, preservePrefixChars);
  const stars = "*".repeat(Math.min(asterisksMax, Math.max(8, trimmed.length - preservePrefixChars)));
  return `${prefix}${stars}[REDACTED:${type}]`;
}

/**
 * Apply matches to text in reverse order so indices stay valid.
 * All other whitespace, newlines, structure is preserved 1:1.
 */
export function applyMatches(text: string, matches: Match[]): string {
  if (matches.length === 0) return text;
  // Sort by start index descending
  const sorted = [...matches].sort((a, b) => b.start - a.start);
  // Dedupe overlapping: keep first encountered (which is the larger one since we sort desc)
  const filtered: Match[] = [];
  let lastEnd = Infinity;
  for (const m of sorted) {
    if (m.end <= lastEnd) {
      filtered.push(m);
      lastEnd = m.start;
    }
  }
  let result = text;
  for (const m of filtered) {
    result = result.slice(0, m.start) + m.replacement + result.slice(m.end);
  }
  return result;
}

/**
 * Check whether the given [start, end) span overlaps an existing REDACTED marker.
 * This prevents re-redacting already-redacted spans.
 */
export function isInsideExistingMarker(text: string, start: number, end: number): boolean {
  // Walk backwards from start to find "[REDACTED"
  let i = start - 1;
  while (i >= 0) {
    const c = text[i];
    if (c === "[") {
      const ahead = text.slice(i, i + 9);
      if (ahead.startsWith("[REDACTED")) return true;
      return false;
    }
    if (c === "]") {
      // Closed marker passed — we're outside
      return false;
    }
    i--;
  }
  return false;
}