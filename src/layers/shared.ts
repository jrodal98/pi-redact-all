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
 * Marker-Span-Cache: tracks existing [REDACTED:...] markers in the text.
 * Built ONCE per text via buildMarkerCache() — used by all layers via isInsideMarker().
 * This avoids the O(n) per-match scan that would make entropy layer O(n²).
 */
export interface MarkerCache {
  /** Sorted array of [start, end) spans that are inside existing [REDACTED:...] markers. */
  spans: [number, number][];
  /** Sorted array of [start, end) spans that are the marker bodies themselves (for reference). */
  markerSpans: [number, number][];
}

export function buildMarkerCache(text: string): MarkerCache {
  const spans: [number, number][] = [];
  const markerSpans: [number, number][] = [];
  // Match [REDACTED:...] where ... is anything that doesn't contain ]
  // The marker body starts AFTER "[REDACTED:" and ends at the closing "]"
  const re = /\[REDACTED[^\]]*\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const markerStart = m.index;
    const markerEnd = m.index + m[0].length;
    markerSpans.push([markerStart, markerEnd]);
    // The "redacted" portion is between prefix and marker (e.g. "AKIA****[REDACTED:Type]")
    // For our purposes, we treat the entire marker span as already-redacted
    spans.push([markerStart, markerEnd]);
  }
  return { spans, markerSpans };
}

/**
 * O(log n) check: is the [start, end) span inside any cached marker?
 */
export function isInsideMarker(cache: MarkerCache, start: number, end: number): boolean {
  const spans = cache.spans;
  // Binary search for first span with end > start
  let lo = 0;
  let hi = spans.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (spans[mid][1] <= start) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  // Check if span at lo contains [start, end)
  if (lo < spans.length && spans[lo][0] <= start && spans[lo][1] >= end) {
    return true;
  }
  // Also check the span right before, in case start is just past it
  if (lo > 0 && spans[lo - 1][0] <= start && spans[lo - 1][1] >= end) {
    return true;
  }
  return false;
}

/**
 * Apply matches to text. All other whitespace, newlines, structure is preserved 1:1.
 *
 * PERFORMANCE: Uses array-parts + join instead of repeated string concatenation,
 * which would be O(n²) for large match counts. This is O(n + m).
 */
export function applyMatches(text: string, matches: Match[]): string {
  if (matches.length === 0) return text;
  // Sort by start index ascending — process left-to-right
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  // Dedupe overlapping: keep the one starting first
  const filtered: Match[] = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      filtered.push(m);
      lastEnd = m.end;
    }
  }
  // Build output as array of parts (each match's text + replacement)
  const parts: string[] = [];
  let cursor = 0;
  for (const m of filtered) {
    if (m.start > cursor) {
      parts.push(text.slice(cursor, m.start));
    }
    parts.push(m.replacement);
    cursor = m.end;
  }
  if (cursor < text.length) {
    parts.push(text.slice(cursor));
  }
  return parts.join("");
}

/**
 * Check whether the given [start, end) span overlaps an existing REDACTED marker.
 * This prevents re-redacting already-redacted spans.
 * @deprecated Use isInsideMarker with buildMarkerCache for O(log n) performance.
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

/**
 * Check whether the given [start, end) span overlaps any existing match in the list.
 * Uses sorted-array binary search for O(log n) performance.
 */
export function hasOverlap(sortedMatches: Match[], start: number, end: number): boolean {
  // Binary search for first match with end > start
  let lo = 0;
  let hi = sortedMatches.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (sortedMatches[mid].end <= start) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  // Check match at lo and lo-1 for overlap
  if (lo < sortedMatches.length) {
    const m = sortedMatches[lo];
    if (start < m.end && end > m.start) return true;
  }
  if (lo > 0) {
    const m = sortedMatches[lo - 1];
    if (start < m.end && end > m.start) return true;
  }
  return false;
}