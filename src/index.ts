import { loadConfig, getDotenvDebug, getConfigPaths } from "./config.js";
import { createSessionStats, recordMatches, recordBlock, formatStats } from "./stats.js";
import { applyRedaction, type ToolResultLike } from "./hooks/tool-result.js";
import { shouldBlock, inputContainsSensitiveSecrets } from "./hooks/tool-call.js";
import { filterUserPrompt, filterProviderPayload, type BeforeAgentStartLike, type BeforeProviderRequestLike } from "./hooks/before-provider.js";
import { filterMessage, type MessageEndLike } from "./hooks/message-end.js";
import { redactText } from "./layers/index.js";
import type { RedactionContext } from "./types.js";

interface ExtensionAPI {
  on(event: string, handler: (...args: unknown[]) => unknown): void;
  registerCommand(name: string, config: { description: string; handler: (args: string, ctx: unknown) => Promise<string> | string }): void;
}

function maskValue(val: string, preserve = 4): string {
  const t = val.trim();
  if (t.length <= preserve) return `${t.slice(0, 1)}*** (${t.length} chars)`;
  const pre = t.slice(0, preserve);
  const masked = "*".repeat(Math.min(12, Math.max(3, t.length - preserve)));
  return `${pre}${masked} (${t.length} chars)`;
}

function validateRegex(pat: string): { valid: boolean; error?: string } {
  try {
    new RegExp(pat);
    return { valid: true };
  } catch (e) {
    return { valid: false, error: (e as Error).message };
  }
}

function formatBlocklistReport(): string {
  const cfg = loadConfig();
  const dotenvDebug = getDotenvDebug();
  const paths = getConfigPaths();
  const lines: string[] = [];
  lines.push(`## pi-redact-all — Active Blocklist`);
  lines.push(``);
  lines.push(`**Config sources:** global \`${paths.global}\` | project \`${paths.project ?? "(none)"}\` ${paths.usedProject ? `(using ${paths.usedProject})` : "(none)"}`);
  lines.push(`**Mode:** ${cfg.mode} | **Layers:** custom=${cfg.layers.custom} vendor=${cfg.layers.vendor} entropy=${cfg.layers.entropy} pii=${cfg.layers.pii}`);
  lines.push(``);

  const regexList = cfg.blocklistRegex ?? [];
  lines.push(`### blocklistRegex (${regexList.length})`);
  if (regexList.length === 0) lines.push(`(none) — add to pi-redact-all.json: "blocklistRegex": ["MY_SECRET_\\\\d+"]`);
  else {
    for (const pat of regexList) {
      const v = validateRegex(pat);
      lines.push(`- \`${pat}\` ${v.valid ? "✓ valid" : `✗ invalid: ${v.error}`}`);
    }
  }
  lines.push(``);

  const literalList = cfg.blocklistLiteral ?? [];
  const dotenvCount = dotenvDebug?.totalValues ?? 0;
  const manualLiteralCount = literalList.length - dotenvCount;
  lines.push(`### blocklistLiteral (${literalList.length}) — ${manualLiteralCount} manual + ${dotenvCount} from dotenv`);
  if (literalList.length === 0) lines.push(`(none)`);
  else {
    const toShow = literalList.slice(0, 20);
    for (const v of toShow) {
      const masked = maskValue(v, cfg.preservePrefixChars);
      lines.push(`- \`${masked}\``);
    }
    if (literalList.length > 20) lines.push(`- … and ${literalList.length - 20} more (use /redact-all-config for raw)`);
  }
  lines.push(``);

  const envList = cfg.blocklistEnv ?? [];
  lines.push(`### blocklistEnv (${envList.length}) — env var names whose *values* are redacted`);
  if (envList.length === 0) lines.push(`(none) — e.g. "blocklistEnv": ["MY_SECRET_TOKEN"]`);
  else {
    for (const name of envList) {
      let val: string | undefined;
      try { val = process.env[name]; } catch {}
      if (val) lines.push(`- \`${name}\` → \`${maskValue(val)}\` ✓ resolved (${val.length} chars)`);
      else lines.push(`- \`${name}\` → (not set / empty) ✗ unresolved`);
    }
  }
  lines.push(``);

  lines.push(`### blocklistDotenv — load .env *values* into blocklistLiteral`);
  lines.push(`- patterns: ${cfg.blocklistDotenv?.length ? cfg.blocklistDotenv.map((p) => `\`${p}\``).join(", ") : "(none)"}`);
  lines.push(`- discover: ${cfg.blocklistDotenvDiscover?.length ? cfg.blocklistDotenvDiscover.join(", ") : "(none)"} (options: gitRoot, cwd, nextToExample)`);
  lines.push(`- excludeKeys: ${cfg.blocklistDotenvExcludeKeys?.length ? cfg.blocklistDotenvExcludeKeys.join(", ") : "(none)"} (e.g. TZ, STORE_MODEL_IN_DB)`);
  if (dotenvDebug) {
    lines.push(`- discovered files (${dotenvDebug.discoveredFiles.length}): ${dotenvDebug.discoveredFiles.length ? dotenvDebug.discoveredFiles.map((p) => `\`${p}\``).join(", ") : "(none)"}`);
    lines.push(`- expanded manual files (${dotenvDebug.expandedManualFiles.length}): ${dotenvDebug.expandedManualFiles.length ? dotenvDebug.expandedManualFiles.slice(0,5).map((p) => `\`${p}\``).join(", ") : "(none)"}${dotenvDebug.expandedManualFiles.length > 5 ? ` +${dotenvDebug.expandedManualFiles.length-5} more` : ""}`);
    lines.push(`- loaded files (${dotenvDebug.loadedFiles.length}):`);
    if (dotenvDebug.loadedFiles.length === 0) lines.push(`  (none)`);
    else {
      for (const f of dotenvDebug.loadedFiles) {
        lines.push(`  - \`${f.path}\`: ${f.valuesCount} values, keys [${f.keys.slice(0,5).join(", ")}${f.keys.length>5?` +${f.keys.length-5} more`:""}]${f.skippedKeys.length ? ` (skipped keys: ${f.skippedKeys.join(", ")})` : ""}`);
      }
    }
    if (dotenvDebug.skippedExampleFiles.length) lines.push(`- skipped example files: ${dotenvDebug.skippedExampleFiles.map((p) => `\`${p}\``).join(", ")}`);
    lines.push(`- total values added: ${dotenvDebug.totalValues} (placeholder skipped: ${dotenvDebug.placeholderSkipped}, short <2 skipped: ${dotenvDebug.shortSkipped})`);
  } else {
    lines.push(`- (no dotenv debug — no dotenv config)`);
  }
  lines.push(``);

  lines.push(`### allowlist (suppressions)`);
  lines.push(`- allowlistRegex (${cfg.allowlistRegex.length}): ${cfg.allowlistRegex.length ? cfg.allowlistRegex.map((p) => `\`${p}\``).join(", ") : "(none)"}`);
  lines.push(`- allowlistLiteral (${cfg.allowlistLiteral.length}): ${cfg.allowlistLiteral.length ? cfg.allowlistLiteral.slice(0,10).map((v) => `\`${maskValue(v)}\``).join(", ") : "(none)"}`);
  lines.push(`- allowlistEnv (${cfg.allowlistEnv.length}): ${cfg.allowlistEnv.length ? cfg.allowlistEnv.join(", ") : "(none)"}`);
  lines.push(``);
  lines.push(`_Tip: /redact-all-config shows raw JSON (values unmasked). /redact-all-blocklist masks values. Values from dotenv are already merged into blocklistLiteral._`);
  return lines.join("\n");
}

export default function (pi: ExtensionAPI) {
  const config = loadConfig();
  const stats = createSessionStats();
  const partialPrivateKeyPaths = new Set<string>();

  const makeContext = (toolName?: string, input?: Record<string, unknown>): RedactionContext => ({
    config,
    partialPrivateKeyPaths,
    toolName,
    inputPath: input ? (input.path as string) : undefined,
    command: input ? (input.command as string) : undefined,
  });

  pi.on("tool_result", async (event: unknown) => {
    const e = event as ToolResultLike;
    const ctx = makeContext(e.toolName, e.input);
    const result = applyRedaction(e, ctx);
    if (e.toolName === "read" && ctx.inputPath) {
      const textItem = e.content.find((c) => c.type === "text");
      if (textItem && textItem.type === "text") {
        if (/-----BEGIN[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text) &&
            !/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
          partialPrivateKeyPaths.add(ctx.inputPath);
        } else if (/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
          partialPrivateKeyPaths.delete(ctx.inputPath);
        }
      }
    }
    if (result.content) {
      let totalMatches = 0;
      for (let i = 0; i < e.content.length; i++) {
        const orig = e.content[i];
        const mod = result.content[i];
        if (orig.type === "text" && mod.type === "text" && orig.text !== mod.text) {
          const scanResult = redactText(orig.text, ctx);
          totalMatches += scanResult.matches.length;
        }
      }
      if (totalMatches > 0) {
        recordMatches(
          stats,
          Array(totalMatches).fill({ start: 0, end: 0, type: "unknown", replacement: "" }),
          e.toolName
        );
      }
    }
    return result;
  });

  pi.on("tool_call", async (event: unknown) => {
    const e = event as ToolResultLike;
    const blockResult = shouldBlock({ toolName: e.toolName, input: e.input }, config);
    if (blockResult) {
      recordBlock(stats);
      return blockResult;
    }
    const inputBlock = inputContainsSensitiveSecrets({ toolName: e.toolName, input: e.input }, config);
    if (inputBlock) {
      recordBlock(stats);
      return inputBlock;
    }
    return undefined;
  });

  pi.on("before_agent_start", async (event: unknown) => {
    const e = event as BeforeAgentStartLike;
    const ctx = makeContext("user_input");
    const result = filterUserPrompt(e, ctx);
    if (result.prompt && result.prompt !== e.prompt) {
      const scanResult = redactText(e.prompt, ctx);
      if (scanResult.matches.length > 0) {
        recordMatches(
          stats,
          scanResult.matches,
          "user_input"
        );
      }
    }
    return result;
  });

  pi.on("message_end", async (event: unknown) => {
    const e = event as MessageEndLike;
    const ctx = makeContext(e.message.role);
    const result = filterMessage(e, ctx);
    if (result.message) {
      recordMatches(
        stats,
        Array(1).fill({ start: 0, end: 0, type: "assistant-message", replacement: "" }),
        `message:${e.message.role}`
      );
    }
    return result;
  });

  pi.on("before_provider_request", async (event: unknown) => {
    const e = event as BeforeProviderRequestLike;
    const ctx = makeContext("provider_payload");
    filterProviderPayload(e, ctx);
    return undefined;
  });

  pi.registerCommand("redact-all-stats", {
    description: "Show pi-redact-all session statistics",
    handler: () => formatStats(stats),
  });

  pi.registerCommand("redact-all-config", {
    description: "Show current pi-redact-all configuration",
    handler: () => JSON.stringify(config, null, 2),
  });

  pi.registerCommand("redact-all-blocklist", {
    description: "Show actively blocklisted regex, literals, env vars and dotenv files (masked)",
    handler: () => formatBlocklistReport(),
  });
}
