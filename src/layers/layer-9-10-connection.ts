// Layer 9 + 10: Connection-Strings & URL-Embedded-Credentials
// Erkennt postgres://user:pass@host und https://user:pass@host

import type { Match, RedactionContext, LayerResult } from "../types.js";
import { buildMarkerCache, isInsideMarker } from "./shared.js";

const CONNECTION_STRING_RE = /\b([a-z][a-z0-9+.\-]*):\/\/([^:\s]+):([^@\s\/]+)@([^\s\/]+)/gi;

const URL_WITH_CREDS_RE = /https?:\/\/([^:\s]+):([^@\s\/]+)@([^\s\/]+)/gi;

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = [];

  // PERFORMANCE: marker cache
  const markerCache = buildMarkerCache(text);

  pushAll(text, CONNECTION_STRING_RE, matches, "Connection String", markerCache, (m) => {
    return {
      start: m.index,
      end: m.index + m[0].length,
      type: "Connection String",
      replacement: `${m[1]}://${m[2]}:[REDACTED:Password]@${m[4]}`,
    };
  });

  pushAll(text, URL_WITH_CREDS_RE, matches, "URL Credentials", markerCache, (m) => {
    return {
      start: m.index,
      end: m.index + m[0].length,
      type: "URL Credentials",
      replacement: `https://${m[1]}:[REDACTED:Password]@${m[3]}`,
    };
  });

  return { matches };
}

function pushAll(
  text: string,
  pattern: RegExp,
  matches: Match[],
  _type: string,
  markerCache: ReturnType<typeof buildMarkerCache>,
  mapper: (m: RegExpExecArray) => { start: number; end: number; type: string; replacement: string } | null
) {
  pattern.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    const result = mapper(m);
    if (!result) continue;
    if (isInsideMarker(markerCache, result.start, result.end)) continue;
    if (matchesOverlapExisting(matches, result.start, result.end)) continue;
    matches.push(result);
  }
}

function matchesOverlapExisting(matches: Match[], start: number, end: number): boolean {
  for (const m of matches) {
    if (start < m.end && end > m.start) return true;
  }
  return false;
}