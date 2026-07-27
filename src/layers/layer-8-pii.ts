// Layer 8: PII-Erkennung
// Erkennt Email, Telefon, IPv4, Kreditkarten, SSN, IBAN

import type { Match, RedactionContext, LayerResult } from "../types.js";
import { buildMarkerCache, isInsideMarker } from "./shared.js";

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

const PHONE_DE_RE = /\b(?:\+49|0)\s?[\d\s\-/()]{8,}\d\b/g;
const PHONE_E164_RE = /\+[1-9]\d{1,14}\b/g;

const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;

const CREDIT_CARD_RE = /\b(?:\d[ -]?){13,19}\b/g;

const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;

const IBAN_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g;

/**
 * Luhn check for credit card numbers.
 */
function isLuhnValid(digits: string): boolean {
  const d = digits.replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = parseInt(d[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = [];

  // PERFORMANCE: marker cache
  const markerCache = buildMarkerCache(text);

  // Email
  pushAll(text, EMAIL_RE, matches, "Email", markerCache);
  // Phone
  pushAll(text, PHONE_DE_RE, matches, "Phone", markerCache);
  pushAll(text, PHONE_E164_RE, matches, "Phone", markerCache);
  // IPv4
  pushAll(text, IPV4_RE, matches, "IPv4", markerCache);
  // Credit Card (with Luhn check)
  pushAll(text, CREDIT_CARD_RE, matches, "Credit Card", markerCache, (value) => {
    const digits = value.replace(/\D/g, "");
    return digits.length >= 13 && isLuhnValid(digits);
  });
  // SSN
  pushAll(text, SSN_RE, matches, "SSN", markerCache);
  // IBAN
  pushAll(text, IBAN_RE, matches, "IBAN", markerCache);

  return { matches };
}

function pushAll(
  text: string,
  pattern: RegExp,
  matches: Match[],
  type: string,
  markerCache: ReturnType<typeof buildMarkerCache>,
  validator?: (value: string) => boolean
) {
  pattern.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    if (isInsideMarker(markerCache, start, end)) continue;
    if (matchesOverlapExisting(matches, start, end)) continue;
    if (validator && !validator(m[0])) continue;

    matches.push({
      start,
      end,
      type,
      replacement: `[REDACTED:${type}]`,
    });
  }
}

function matchesOverlapExisting(matches: Match[], start: number, end: number): boolean {
  for (const m of matches) {
    if (start < m.end && end > m.start) return true;
  }
  return false;
}