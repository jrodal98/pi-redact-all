import type { Match, RedactionContext, LayerResult } from "../types.js";
import { buildMarker, buildMarkerCache, isAllowlisted, isInsideMarker } from "./shared.js";

function compileRegexes(patterns: string[]): { re: RegExp; raw: string }[] {
  const out: { re: RegExp; raw: string }[] = [];
  for (const raw of patterns) {
    if (!raw || typeof raw !== "string") continue;
    try {
      const slashMatch = raw.match(/^\/(.+)\/([gimsuy]*)$/);
      let re: RegExp;
      if (slashMatch) {
        const flags = slashMatch[2].includes("g") ? slashMatch[2] : slashMatch[2] + "g";
        re = new RegExp(slashMatch[1], flags);
      } else {
        re = new RegExp(raw, "g");
      }
      out.push({ re, raw });
    } catch (err) {
      console.error(`[pi-redact-all] Invalid customRegex/blocklistRegex pattern skipped: ${raw}`, err);
    }
  }
  return out;
}

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = [];
  const markerCache = buildMarkerCache(text);

  const regexSources = dedupe([
    ...(ctx.config.blocklistRegex ?? []),
    ...(ctx.config.customRegex ?? []),
  ]);
  if (regexSources.length > 0) {
    const compiled = compileRegexes(regexSources);
    for (const { re } of compiled) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        const start = m.index;
        const end = start + m[0].length;
        if (isInsideMarker(markerCache, start, end)) continue;
        if (matchesOverlapExisting(matches, start, end)) continue;
        if (isAllowlisted(m[0], ctx)) continue;
        matches.push({
          start,
          end,
          type: "Custom Pattern",
          replacement: buildMarker(m[0], "Custom Pattern", ctx.config.preservePrefixChars, ctx.config.asterisksMax),
        });
      }
    }
  }

  const literals = dedupe([
    ...(ctx.config.blocklistLiteral ?? []),
    ...(ctx.config.customLiterals ?? []),
  ].filter((s) => typeof s === "string" && s.length >= 2));
  for (const lit of literals) {
    if (isAllowlisted(lit, ctx)) continue;
    let idx = 0;
    while (idx < text.length) {
      const found = text.indexOf(lit, idx);
      if (found === -1) break;
      const start = found;
      const end = found + lit.length;
      if (!isInsideMarker(markerCache, start, end) && !matchesOverlapExisting(matches, start, end)) {
        matches.push({
          start,
          end,
          type: "Custom Secret",
          replacement: buildMarker(lit, "Custom Secret", ctx.config.preservePrefixChars, ctx.config.asterisksMax),
        });
      }
      idx = end;
    }
  }

  const envNames = dedupe([
    ...(ctx.config.blocklistEnv ?? []),
    ...(ctx.config.envVars ?? []),
  ].filter((s) => typeof s === "string" && s.length > 0));
  for (const name of envNames) {
    let value: string | undefined;
    try {
      value = process.env[name];
    } catch {
      continue;
    }
    if (!value || value.length < 2) continue;
    if (value.trim().length < 2) continue;
    if (isAllowlisted(value, ctx)) continue;
    let idx = 0;
    while (idx < text.length) {
      const found = text.indexOf(value, idx);
      if (found === -1) break;
      const start = found;
      const end = found + value.length;
      if (!isInsideMarker(markerCache, start, end) && !matchesOverlapExisting(matches, start, end)) {
        matches.push({
          start,
          end,
          type: `Env Var ${name}`,
          replacement: buildMarker(value, `Env Var ${name}`, ctx.config.preservePrefixChars, ctx.config.asterisksMax),
        });
      }
      idx = end;
    }
  }

  if (matches.length > 1) matches.sort((a, b) => a.start - b.start);
  return { matches };
}

function dedupe(arr: string[]): string[] {
  return [...new Set(arr)];
}

function matchesOverlapExisting(matches: Match[], start: number, end: number): boolean {
  for (const m of matches) {
    if (start < m.end && end > m.start) return true;
  }
  return false;
}
