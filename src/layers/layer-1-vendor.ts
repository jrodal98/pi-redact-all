// Layer 1: Strukturierte Vendor-Patterns
// Erkennt API-Keys, Tokens, Credentials von bekannten Herstellern

import type { Match, RedactionContext, LayerResult } from "../types.js";
import { buildMarker, buildMarkerCache, isInsideMarker, hasOverlap } from "./shared.js";

interface Pattern {
  name: string;
  pattern: RegExp;
}

const PATTERNS: Pattern[] = [
  { name: "AWS Access Key", pattern: /\bAKIA[A-Z0-9]{16}\b/g },
  { name: "AWS Temp Access Key", pattern: /\bASIA[A-Z0-9]{16}\b/g },
  {
    name: "AWS Secret Key",
    pattern: /\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secret_access_key|SecretAccessKey)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40,}["']?/g,
  },
  { name: "Bearer Token", pattern: /\bBearer\s+[a-zA-Z0-9._\-]{20,}/g },
  { name: "OpenAI/Anthropic API Key", pattern: /\bsk-[a-zA-Z0-9._\-]{20,}\b/g },
  { name: "Stripe Live Key", pattern: /\bsk_live_[a-zA-Z0-9]{20,}\b/g },
  { name: "Stripe Test Key", pattern: /\bsk_test_[a-zA-Z0-9]{20,}\b/g },
  { name: "Hetzner Token", pattern: /(?:HCLOUD_TOKEN|hcloud_token|token)\s*[:=]\s*["']?[a-f0-9]{64}\b/gi },
  { name: "GitHub Token", pattern: /\bgh[pousr]_[a-zA-Z0-9]{36,}\b/g },
  { name: "GitHub Fine-grained PAT", pattern: /\bgithub_pat_[a-zA-Z0-9_]{20,}\b/g },
  { name: "JWT", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: "Slack Token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
  { name: "GitLab Token", pattern: /\bglpat-[A-Za-z0-9_\-]{20,}\b/g },
  { name: "Google API Key", pattern: /\bAIza[A-Za-z0-9_\-]{35}\b/g },
  { name: "npm Token", pattern: /\bnpm_[A-Za-z0-9]{36,}\b/g },
  { name: "SendGrid API Key", pattern: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{32,}\b/g },
  { name: "Tavily API Key", pattern: /\btvly-[a-zA-Z0-9_\-]{20,}\b/g },
  { name: "Brave API Key", pattern: /\bBSA[A-Z0-9]{20,}\b/g },
  { name: "Firecrawl API Key", pattern: /\bfc-[a-f0-9]{32}\b/g },
  {
    name: "Kagi API Key",
    pattern: /\b[a-zA-Z0-9_\-]{40,}\.[a-zA-Z0-9_\-]{40,}\b/g,
  },
];

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = [];
  const allowlist = compileAllowlist(ctx.config.allowlistRegex);

  // PERFORMANCE: Build marker cache once, use O(log n) checks per match
  const markerCache = buildMarkerCache(text);

  for (const { name, pattern } of PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(text)) !== null) {
      const start = m.index;
      const end = start + m[0].length;
      if (isInsideMarker(markerCache, start, end)) continue;
      // matches list not yet sorted — use O(n) but list grows linearly with patterns
      if (matchesOverlapExisting(matches, start, end)) continue;
      if (allowlist.test(m[0])) continue;
      matches.push({
        start,
        end,
        type: name,
        replacement: buildMarker(m[0], name, ctx.config.preservePrefixChars, ctx.config.asterisksMax),
      });
    }
  }

  return { matches };
}

function matchesOverlapExisting(matches: Match[], start: number, end: number): boolean {
  for (const m of matches) {
    if (start < m.end && end > m.start) return true;
  }
  return false;
}

function compileAllowlist(patterns: string[]): RegExp {
  if (patterns.length === 0) return /(?!)/; // never matches
  try {
    return new RegExp(patterns.join("|"), "g");
  } catch {
    return /(?!)/;
  }
}